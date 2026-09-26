"""
In-process scan registry.

Owns the lifecycle of background scans: one :class:`asyncio.Task` per scan, an
event fan-out for SSE subscribers, and cooperative cancellation.

This is deliberately in-process. It is the right size for a single-node
deployment and it keeps the scan state next to the orchestrator that owns it.
Running more than one API replica would need a shared broker (Redis pub/sub)
and a durable queue; that trade is noted in the docs rather than half-built
here, because a broker that silently loses events is worse than one process.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.core.logging_config import get_logger
from app.models.enums import ScanStatus
from app.services.orchestrator import ScanOutcome

logger = get_logger(__name__)

#: How many past events to replay to a subscriber that connects mid-scan.
REPLAY_BUFFER = 500

#: Sentinel broadcast used to close every subscriber when a scan ends.
_SENTINEL = object()


@dataclass
class RunningScan:
    """A scan executing in the background."""

    scan_id: str
    project_id: str
    repository: Path
    task: Optional[asyncio.Task] = None
    events: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=REPLAY_BUFFER))
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    outcome: Optional[ScanOutcome] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished: bool = False
    cancelled: bool = False

    # -- event fan-out --------------------------------------------------
    def publish(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        for queue in list(self.subscribers):
            # A subscriber that stops draining must not block the scan.
            if queue.full():
                with contextlib.suppress(asyncio.QueueFull):
                    queue.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(event)

    def close(self) -> None:
        self.finished = True
        for queue in list(self.subscribers):
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(_SENTINEL)

    async def subscribe(self, *, replay: bool = True) -> asyncio.Queue:
        """Register a subscriber, optionally replaying what already happened."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        if replay:
            for event in self.events:
                with contextlib.suppress(asyncio.QueueFull):
                    queue.put_nowait(event)
            if self.finished:
                with contextlib.suppress(asyncio.QueueFull):
                    queue.put_nowait(_SENTINEL)
        self.subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self.subscribers.discard(queue)

    def snapshot(self) -> dict[str, Any]:
        last = self.events[-1] if self.events else {}
        return {
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "status": ScanStatus.CANCELLED.value
            if self.cancelled
            else (ScanStatus.COMPLETED.value if self.finished else ScanStatus.RUNNING.value),
            "started_at": self.started_at.isoformat(),
            "finished": self.finished,
            "cancelled": self.cancelled,
            "event_count": len(self.events),
            "progress": last.get("progress", 0.0),
            "phase": last.get("phase", ""),
            "message": last.get("message", ""),
        }


class ScanManager:
    """Registry of live and recently finished scans."""

    def __init__(self) -> None:
        self._scans: dict[str, RunningScan] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    def register(self, scan_id: str, project_id: str, repository: Path) -> RunningScan:
        running = RunningScan(scan_id=scan_id, project_id=project_id, repository=repository)
        self._scans[scan_id] = running
        return running

    def get(self, scan_id: str) -> RunningScan | None:
        return self._scans.get(scan_id)

    def is_running(self, scan_id: str) -> bool:
        running = self._scans.get(scan_id)
        return bool(running and not running.finished)

    def start(self, running: RunningScan, coro_factory) -> asyncio.Task:
        """Run ``coro_factory(running)`` in the background, self-cleaning."""
        running.task = asyncio.create_task(
            self._supervise(running, coro_factory), name=f"scan-{running.scan_id}"
        )
        return running.task

    async def _supervise(self, running: RunningScan, coro_factory) -> None:
        try:
            running.outcome = await coro_factory(running)
        except asyncio.CancelledError:
            running.cancelled = True
            running.publish(
                {
                    "scan_id": running.scan_id,
                    "phase": "cancelled",
                    "message": "Scan cancelled by request",
                    "progress": 100.0,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            raise
        except Exception as exc:
            logger.exception("scan %s crashed", running.scan_id)
            running.publish(
                {
                    "scan_id": running.scan_id,
                    "phase": "failed",
                    "message": f"Scan failed: {exc}",
                    "progress": 100.0,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            if running.outcome is not None:
                running.outcome.status = ScanStatus.FAILED
                running.outcome.errors.append(str(exc))
        finally:
            running.close()

    async def cancel(self, scan_id: str) -> bool:
        running = self._scans.get(scan_id)
        if not running or not running.task or running.finished:
            return False
        running.task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await running.task
        return True

    async def shutdown(self) -> None:
        """Cancel everything still running; called on application shutdown."""
        tasks = [r.task for r in self._scans.values() if r.task and not r.finished]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    def list_running(self) -> list[dict[str, Any]]:
        return [r.snapshot() for r in self._scans.values() if not r.finished]


#: Process-wide registry. The API creates it on startup and hands it to routes.
manager = ScanManager()

__all__ = ["ScanManager", "RunningScan", "manager"]
