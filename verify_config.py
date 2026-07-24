"""Shared model-profile resolution for the independent Verify Agent."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace

from claudeagent.model_config import ModelProfile, resolve_api_key, resolve_named_profile
from claudeagent.verify_agent import (
    DEFAULT_VERDICT_CALLS,
    VerifyAgentConfig,
    verify_agent_config_digest,
    verify_agent_config_from_profile,
)


@dataclass(frozen=True)
class ResolvedVerifyAgentSettings:
    """Verifier config plus the non-secret provider identity used to build it."""

    config: VerifyAgentConfig
    profile_name: str
    api_key_env: str
    config_digest: str


def _effective_main_profile(
    args: argparse.Namespace,
    profile: ModelProfile,
) -> ModelProfile:
    """Mirror main-agent CLI/profile precedence without mutating ``args``."""
    return replace(
        profile,
        base_url=getattr(args, "base_url", "") or profile.base_url,
        model=getattr(args, "model", "") or profile.model,
        api_timeout=(
            profile.api_timeout
            if profile.api_timeout is not None
            else int(getattr(args, "api_timeout", 240))
        ),
        api_max_retries=(
            profile.api_max_retries
            if profile.api_max_retries is not None
            else int(getattr(args, "api_max_retries", 3))
        ),
        api_turn_retries=(
            profile.api_turn_retries
            if profile.api_turn_retries is not None
            else int(getattr(args, "api_turn_retries", 1))
        ),
    )


def resolve_verify_agent_settings(
    args: argparse.Namespace,
    *,
    main_profile: ModelProfile | None = None,
    require_api_key: bool = False,
) -> ResolvedVerifyAgentSettings:
    """Resolve the verifier profile, provider settings, and stable config digest.

    An explicit ``--verify-model-profile`` is isolated from main-agent CLI
    provider overrides. Otherwise the verifier inherits the main profile plus
    the main agent's effective base URL, model, and timeout/retry settings.
    Batch and dry-run callers leave ``require_api_key`` false to compute the
    exact digest with an empty credential placeholder.
    """
    requested = str(getattr(args, "verify_model_profile", "") or "")
    if requested:
        selected_profile = resolve_named_profile(requested)
    else:
        inherited = main_profile or resolve_named_profile(
            str(getattr(args, "model_profile", "") or "")
        )
        selected_profile = _effective_main_profile(args, inherited)

    api_key = resolve_api_key(selected_profile) if require_api_key else ""
    if require_api_key and not api_key:
        raise ValueError(
            f"API key for verifier profile {selected_profile.name!r} is not set "
            f"(env var {selected_profile.api_key_env!r})"
        )
    config = verify_agent_config_from_profile(
        selected_profile,
        api_key,
        verdict_calls=int(getattr(args, "verify_verdict_calls", DEFAULT_VERDICT_CALLS)),
        strict=not bool(getattr(args, "no_strict", False)),
    )
    return ResolvedVerifyAgentSettings(
        config=config,
        profile_name=selected_profile.name,
        api_key_env=selected_profile.api_key_env,
        config_digest=verify_agent_config_digest(config),
    )


def expected_verify_agent_signature(
    args: argparse.Namespace,
    *,
    main_profile: ModelProfile | None = None,
) -> tuple[str, str]:
    """Return the artifact mode/digest pair required for safe batch resume."""
    mode = str(getattr(args, "verify_agent", "on") or "on")
    if mode == "off":
        return "off", ""
    settings = resolve_verify_agent_settings(args, main_profile=main_profile)
    return "on", settings.config_digest
