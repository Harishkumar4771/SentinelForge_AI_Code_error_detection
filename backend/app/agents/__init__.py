"""
Agent package (spec §5, §15).

Each agent implements :class:`~app.agents.base.BaseAgent` and can be run
independently::

    result = await SecurityAgent().run(context)

The orchestrator runs them in a fixed order, feeding each agent the
correlated findings of the previous ones, so later agents can corroborate
earlier ones. Agents never talk to each other directly.
"""

from app.agents.base import AgentContext, BaseAgent, severity_sort_key
from app.agents.bug_hunter import BugHunterAgent
from app.agents.fix_agent import FixAgent, PatchVerdict
from app.agents.security_agent import SecurityAgent
from app.agents.testing_agent import TestingAgent

#: Canonical execution order. Security and Bug Hunter run first (they produce
#: the findings), Testing second (it needs findings to target), Fix last (it
#: needs both findings and tests).
AGENT_REGISTRY: tuple[type[BaseAgent], ...] = (
    SecurityAgent,
    BugHunterAgent,
    TestingAgent,
    FixAgent,
)

__all__ = [
    "AGENT_REGISTRY",
    "AgentContext",
    "BaseAgent",
    "BugHunterAgent",
    "FixAgent",
    "PatchVerdict",
    "SecurityAgent",
    "TestingAgent",
    "severity_sort_key",
]
