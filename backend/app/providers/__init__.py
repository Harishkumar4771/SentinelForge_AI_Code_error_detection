"""
AI provider package (spec §4).

``AIProvider`` is the only thing business logic is allowed to depend on.
"""

from app.providers.base import (
    SYSTEM_PROMPTS,
    AIProvider,
    Completion,
    GenerationRequest,
    IBMWatsonxProvider,
    MockProvider,
    ProviderError,
    ProviderResponseError,
    extract_json,
    get_provider,
    set_provider,
)

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
