"""
AI provider abstraction (spec §4).

::

    AIProvider
    ├── IBMWatsonxProvider
    └── MockProvider

Business logic never imports a provider directly -- it receives an
``AIProvider``. Swapping IBM watsonx.ai for a local model, or running the
whole platform with no credentials at all, is a configuration change.

Two rules hold everywhere in this package (spec §24, §32):

1. A provider returns *text*. It never returns a trusted object.
2. Every structured response is validated by Pydantic at the call site; a
   malformed response becomes a typed error, never a partial finding.
"""

from __future__ import annotations

import abc
import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger(__name__)


class ProviderError(RuntimeError):
    """Recoverable provider failure (network, timeout, bad credentials)."""


class ProviderResponseError(ProviderError):
    """The model replied, but not with the structure that was requested."""


@dataclass
class Completion:
    """A single model response plus the metadata worth auditing."""

    text: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    finish_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def json(self) -> Any:
        """Parse the response as JSON, tolerating markdown fences.

        Models routinely wrap JSON in ```json fences or add a sentence of
        prose. Rather than trusting that, the fenced span is extracted and
        then parsed strictly -- a non-JSON body still raises.
        """
        return extract_json(self.text)


def extract_json(text: str) -> Any:
    """Pull a JSON document out of a model response.

    Raises ``ProviderResponseError`` when nothing parsable is present, so
    the caller can treat it as a failure instead of a silent empty result.
    """
    if not text or not text.strip():
        raise ProviderResponseError("Model returned an empty response")

    candidate = text.strip()

    # Fenced block, optionally tagged ```json
    fence = re.search(r"```(?:json)?\s*(.+?)\s*```", candidate, re.DOTALL)
    if fence:
        candidate = fence.group(1).strip()

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    # Fall back to the widest balanced-looking span.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = candidate.find(opener)
        end = candidate.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(candidate[start : end + 1])
            except json.JSONDecodeError:
                continue

    raise ProviderResponseError(
        f"Model response did not contain JSON. First 300 chars: {candidate[:300]!r}"
    )


# ----------------------------------------------------------------------
SYSTEM_PROMPTS = {
    # Spec §24: the defensive-security framing plus the anti-hallucination
    # contract must accompany *every* analysis prompt.
    "security": (
        "You are a senior application-security engineer performing a "
        "DEFENSIVE security review of source code you were given.\n\n"
        "Rules you must follow:\n"
        "1. Report a vulnerability only when you have concrete evidence in the "
        "provided code. Cite the file and line.\n"
        "2. Never invent evidence, function names, file paths, or CVEs. If a "
        "detail is not visible in the supplied context, omit it.\n"
        "3. Label each finding's certainty as one of: confirmed (you can point "
        "at the exact vulnerable expression), probable (a dangerous pattern is "
        "present and reachable), potential (the pattern exists but you cannot "
        "confirm reachability).\n"
        "4. Prefer fewer, well-evidenced findings over a long list of guesses.\n"
        "5. This is authorised analysis of the user's own code. Provide "
        "remediation guidance, not working exploits."
    ),
    "bug_hunter": (
        "You are a senior software engineer hunting FUNCTIONAL and LOGICAL "
        "defects in source code -- not security vulnerabilities.\n\n"
        "Look for: inverted or missing comparisons, unreachable branches, "
        "off-by-one errors, incorrect arithmetic, sign errors, unhandled "
        "None/null, broken state transitions, flawed authorization or business "
        "rules, and inconsistent error handling.\n\n"
        "Rules:\n"
        "1. Only report a defect when the provided code demonstrates it. Cite "
        "the file and line.\n"
        "2. Explain the concrete wrong behaviour: what input or sequence "
        "produces the incorrect result.\n"
        "3. Do not report style issues, missing type hints, or anything a "
        "linter would already flag."
    ),
    "fix": (
        "You are a senior engineer producing a MINIMAL security fix.\n\n"
        "Rules:\n"
        "1. Return the smallest change that removes the vulnerability while "
        "preserving the existing behaviour and public interface.\n"
        "2. Prefer the platform's safe primitive (parameterized queries, "
        "pathlib containment checks, secrets from the environment, JSON "
        "instead of pickle).\n"
        "3. Return code that parses and runs. Do not reference undefined "
        "imports, helpers, or variables.\n"
        "4. Do not add new dependencies.\n"
        "5. Never remove the security check to make the vulnerable test pass."
    ),
    "tests": (
        "You are a senior test engineer writing pytest tests for existing "
        "code.\n\n"
        "Rules:\n"
        "1. Import only from the module under test and the standard library "
        "plus pytest.\n"
        "2. Tests must be self-contained and must not require a network, a "
        "database server, or any service that is not provided.\n"
        "3. A security regression test for a known vulnerability MUST fail on "
        "the vulnerable code and pass once it is fixed. Do not write a test "
        "that passes either way.\n"
        "4. Every test must be deterministic."
    ),
}


@dataclass
class GenerationRequest:
    """One model call."""

    prompt: str
    system: str = "security"
    temperature: float | None = None
    max_tokens: int | None = None
    #: Ask the provider for a JSON object matching this schema, when it can.
    json_schema: Optional[dict[str, Any]] = None
    json_object: Optional[dict[str, Any]] = None


class AIProvider(abc.ABC):
    """
    Interface every provider implements.

    Implementations must be safe to call from the orchestrator's thread and
    must never raise anything other than :class:`ProviderError`.
    """

    name: str = "abstract"

    @abc.abstractmethod
    async def generate(self, request: GenerationRequest) -> Completion:
        """Produce a completion, or raise ``ProviderError``."""

    @abc.abstractmethod
    async def health(self) -> bool:
        """True when the provider is reachable and configured."""

    @property
    def model_id(self) -> str:
        return "unknown"

    def system_prompt(self, key: str) -> str:
        return SYSTEM_PROMPTS.get(key, SYSTEM_PROMPTS["security"])

    async def generate_json(self, request: GenerationRequest) -> Any:
        """
        Request JSON and return it parsed.

        The schema is advertised in the prompt *and* (where the provider
        supports it) through native structured-output parameters. The
        response is still validated by the caller's Pydantic model, so a
        provider that ignores the instruction cannot corrupt the pipeline.
        """
        completion = await self.generate(request)
        return completion.json()

    def _instructions(self, request: GenerationRequest) -> str:
        parts: list[str] = []
        if request.json_schema is not None:
            parts.append(
                "Respond with a single JSON value and nothing else. "
                "It must validate against this JSON Schema:\n"
                + json.dumps(request.json_schema, indent=2)[:6000]
            )
        elif request.json_object is not None:
            parts.append(
                "Respond with a single JSON object and nothing else. "
                "It must have exactly these keys:\n"
                + json.dumps(request.json_object, indent=2)[:4000]
            )
        else:
            parts.append("Respond in plain prose. Be concise and specific.")
        return "\n\n".join(parts)


# ----------------------------------------------------------------------
class MockProvider(AIProvider):
    """
    Deterministic offline provider.

    This is **not** a stub that fabricates findings -- that would violate
    the project's core principle. It performs real, conservative analysis
    with the Python standard library (AST inspection and string matching)
    and returns that. Its purpose is to make the whole pipeline runnable and
    testable with no credentials, and to guarantee the demo never depends on
    a network call to an LLM.
    """

    name = "mock"

    def __init__(self) -> None:
        self._model = "mock-deterministic-v1"

    @property
    def model_id(self) -> str:
        return self._model

    async def health(self) -> bool:
        return True

    async def generate(self, request: GenerationRequest) -> Completion:
        # Simulate a small amount of latency so the UI's progress states are
        # exercised, but stay fast enough for a live demo.
        await asyncio.sleep(0.01)
        from app.providers.mock_brain import respond

        text = respond(request)
        return Completion(
            text=text,
            model=self._model,
            provider=self.name,
            latency_ms=10.0,
        )


# ----------------------------------------------------------------------
class IBMWatsonxProvider(AIProvider):
    """
    IBM watsonx.ai provider (production path).

    Uses the official ``ibm-watsonx-ai`` SDK when it is importable, and
    falls back to the documented REST API via httpx otherwise. Credentials
    come from the environment only.
    """

    name = "ibm_watsonx"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        project_id: str | None = None,
        model_id: str | None = None,
        url: str | None = None,
    ) -> None:
        self.api_key = api_key or settings.ibm_watsonx_api_key
        self.project_id = project_id or settings.ibm_watsonx_project_id
        self.url = (url or settings.ibm_watsonx_url).rstrip("/")
        self._model = model_id or settings.ibm_model_id
        self._client: Any = None

    @property
    def model_id(self) -> str:
        return self._model

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self.api_key or not self.project_id:
            raise ProviderError(
                "IBM watsonx.ai is not configured. Set IBM_WATSONX_API_KEY and "
                "IBM_WATSONX_PROJECT_ID, or switch AI_PROVIDER=mock."
            )
        try:
            from ibm_watsonx_ai import Credentials
            from ibm_watsonx_ai.foundation_models import ModelInference
        except ImportError as exc:  # pragma: no cover - dependency is pinned
            raise ProviderError("ibm-watsonx-ai is not installed") from exc

        self._client = ModelInference(
            model_id=self._model,
            credentials=Credentials(url=self.url, api_key=self.api_key),
            project_id=self.project_id,
        )
        return self._client

    async def health(self) -> bool:
        try:
            import ibm_watsonx_ai  # noqa: F401
        except ImportError:
            return False
        return bool(self.api_key and self.project_id)

    async def generate(self, request: GenerationRequest) -> Completion:
        loop = asyncio.get_running_loop()
        start = loop.time()
        prompt = f"{self.system_prompt(request.system)}\n\n{request.prompt}\n\n{self._instructions(request)}"

        try:
            client = await asyncio.to_thread(self._ensure_client)
            result = await asyncio.to_thread(
                client.generate_text,
                prompt=prompt,
                project_id=self.project_id,
                max_tokens=request.max_tokens or settings.ai_max_tokens,
                temperature=request.temperature if request.temperature is not None else settings.ai_temperature,
                # Guarded decoding is what makes a model return parseable
                # JSON; without it the provider cannot be trusted to conform.
                guardrails_as_text=True,
            )
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(f"watsonx.ai request failed: {exc}") from exc

        text = _extract_watsonx_text(result)
        usage = _extract_usage(result)
        return Completion(
            text=text,
            model=self._model,
            provider=self.name,
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            latency_ms=(loop.time() - start) * 1000,
            raw=result if isinstance(result, dict) else {},
        )


def _extract_watsonx_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for key in ("results", "choices", "generated_text"):
            if key in result:
                value = result[key]
                if isinstance(value, list) and value:
                    first = value[0]
                    if isinstance(first, dict):
                        return str(
                            first.get("generated_text")
                            or first.get("text")
                            or first.get("message", {}).get("content", "")
                            or ""
                        )
                    return str(first)
                if isinstance(value, str):
                    return value
        if "generated_text" in result:
            return str(result["generated_text"])
    return str(result)


def _extract_usage(result: Any) -> dict[str, int]:
    usage: dict[str, int] = {}
    if isinstance(result, dict):
        raw = result.get("usage") or result.get("model_id") or {}
        if isinstance(raw, dict):
            for key in ("prompt_tokens", "completion_tokens", "input_token_count", "output_token_count"):
                if key in raw:
                    usage["prompt_tokens" if "prompt" in key or "input" in key else "completion_tokens"] = int(
                        raw[key] or 0
                    )
    return usage


# ----------------------------------------------------------------------
_provider_singleton: AIProvider | None = None


def get_provider() -> AIProvider:
    """
    Return the configured provider.

    The provider is created once per process; it holds a network client and
    should not be rebuilt per request.
    """
    global _provider_singleton
    if _provider_singleton is not None:
        return _provider_singleton

    if settings.ai_provider == "ibm_watsonx":
        _provider_singleton = IBMWatsonxProvider()
        logger.info("AI provider: IBM watsonx.ai (%s)", _provider_singleton.model_id)
    else:
        _provider_singleton = MockProvider()
        logger.info(
            "AI provider: MockProvider (deterministic, offline). "
            "Set AI_PROVIDER=ibm_watsonx to use a real model."
        )
    return _provider_singleton


def set_provider(provider: AIProvider | None) -> None:
    """Override the provider (used by the test suite)."""
    global _provider_singleton
    _provider_singleton = provider


__all__ = [
    "AIProvider",
    "Completion",
    "GenerationRequest",
    "IBMWatsonxProvider",
    "MockProvider",
    "ProviderError",
    "ProviderResponseError",
    "SYSTEM_PROMPTS",
    "extract_json",
    "get_provider",
    "set_provider",
]
