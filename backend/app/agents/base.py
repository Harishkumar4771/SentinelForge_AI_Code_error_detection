"""
Agent framework (spec §5, §15).

Every agent implements :class:`BaseAgent` and returns an
:class:`~app.schemas.finding.AgentResult`. The orchestrator depends only on
this interface, which is what keeps a clean migration path to LangGraph: a
graph node is a thin wrapper over ``BaseAgent.run``.

Lifecycle guarantees:

* a raised exception inside an agent is captured, logged and turned into a
  ``FAILED`` result -- one broken agent never aborts the scan (spec §27);
* progress is reported through :class:`AgentContext` so the UI can render a
  live timeline;
* every execution is timed and persisted as an ``AgentExecution`` row.
"""

from __future__ import annotations

import abc
import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.logging_config import get_logger
from app.core.security import redact
from app.models.enums import AgentName, AgentStatus
from app.schemas.finding import AgentFinding, AgentResult
from app.services.repository import RepositorySnapshot

logger = get_logger(__name__)

#: Signature of a progress callback.
ProgressCallback = Callable[[str, float, dict[str, Any]], Awaitable[None] | None]


@dataclass
class AgentContext:
    """
    Everything an agent is allowed to see.

    Passing the repository snapshot in (rather than letting agents touch
    the filesystem or a database) is what makes agents testable in
    isolation and keeps the security boundary in one place.
    """

    scan_id: str
    project_id: str
    snapshot: RepositorySnapshot
    scan_root: Optional[Any] = None
    on_progress: Optional[ProgressCallback] = None
    #: Stamped onto every progress event so the UI can attribute it. One
    #: context per agent, so this is always the reporting agent's own name.
    agent_name: str = ""
    #: Findings already produced by earlier agents, for deduplication.
    prior_findings: list[AgentFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    async def report(
        self, message: str, progress: float = 0.0, **payload: Any
    ) -> None:
        """Emit a progress tick. Never raises -- UI must not break a scan."""
        if self.on_progress is None:
            return
        # The agent name is set here rather than at each call site so an
        # internal step cannot forget it and land unattributed in the feed.
        payload.setdefault("agent", self.agent_name or self.__class__.__name__)
        try:
            result = self.on_progress(message, progress, payload)
            if asyncio.iscoroutine(result):
                await result
        except Exception:  # pragma: no cover - defensive
            logger.debug("progress callback failed for %s", message, exc_info=True)

    def file_source(self, relative_path: str) -> str | None:
        return self.snapshot.read(relative_path)


class BaseAgent(abc.ABC):
    """Abstract agent. Subclasses implement :meth:`execute`."""

    name: str = "agent"
    agent_enum: AgentName = AgentName.SECURITY
    description: str = ""

    @abc.abstractmethod
    async def execute(self, context: AgentContext) -> AgentResult:
        """Do the work. May raise; :meth:`run` contains the blast radius."""

    # -- template method ------------------------------------------------
    async def run(self, context: AgentContext) -> AgentResult:
        """
        Run the agent with failure containment and timing.

        This is the only entry point the orchestrator uses.
        """
        started = time.perf_counter()
        # Stamp the context so every internal progress tick is attributed to
        # this agent without each call site having to repeat the name.
        context.agent_name = self.name
        await context.report(
            f"{self.name} started", 0.0,
            agent=self.name, status=AgentStatus.RUNNING.value,
        )

        try:
            result = await asyncio.wait_for(
                self.execute(context),
                timeout=self.timeout(context),
            )
        except asyncio.TimeoutError:
            duration = (time.perf_counter() - started) * 1000
            logger.error("%s timed out after %.0fs", self.name, duration / 1000)
            result = AgentResult(
                agent_name=self.name,
                status="FAILED",
                message=f"{self.name} exceeded its time budget and was stopped.",
                error="timeout",
                metrics={"duration_ms": duration},
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            duration = (time.perf_counter() - started) * 1000
            # Redact before logging: an agent may be holding a credential it
            # found, and that must never reach the log file verbatim.
            logger.exception("%s failed: %s", self.name, redact(str(exc)))
            result = AgentResult(
                agent_name=self.name,
                status="FAILED",
                message=f"{self.name} failed: {redact(str(exc))[:300]}",
                error=type(exc).__name__,
                metrics={"duration_ms": duration},
            )
        else:
            result.metrics.setdefault(
                "duration_ms", (time.perf_counter() - started) * 1000
            )
            logger.info(
                "%s finished: status=%s findings=%d tests=%d in %.0fms",
                self.name, result.status, len(result.findings),
                len(result.test_cases), result.metrics.get("duration_ms", 0),
            )

        await context.report(
            f"{self.name} {result.status.lower()}",
            1.0,
            agent=self.name,
            status=AgentStatus.COMPLETED.value
            if result.status == "COMPLETED"
            else AgentStatus.FAILED.value,
            findings=len(result.findings),
            tests=len(result.test_cases),
        )
        return result

    def timeout(self, context: AgentContext) -> int:
        """Per-agent wall-clock budget."""
        return 900


def severity_sort_key(finding: AgentFinding) -> tuple:
    """Order findings most-severe-first, then by confidence."""
    return (-finding.severity.rank, -finding.confidence, finding.file_path or "")
