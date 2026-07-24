"""Backend model/provider configuration for the agent loop.

All provider settings live in ``model_config.json`` next to this module: a set
of named *profiles* (each carrying base_url, model, reasoning effort, the env
var that holds the API key, and optional retry/timeout knobs), an
``active_profile`` used when none is requested, and short ``aliases``.

Resolution precedence is **CLI flag > config profile field > nothing**. The old
``OPENAI_BASE_URL`` / ``OPENAI_MODEL`` / bare ``OPENAI_API_KEY`` environment
defaults are intentionally gone: the config file is the single source of truth
for *which* backend to talk to.

The API key itself is still read from the environment, but only via the env var
named by the chosen profile's ``api_key_env`` (different providers use different
keys, so the key cannot live in the config file). A profile may additionally
name an ``api_key_file`` + ``api_key_field`` JSON file to read the key from when
the env var is unset - this lets a profile reach a key that already lives in a
non-env location (e.g. ``~/.codex/auth.json``) without copying it anywhere new.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONFIG_PATH = Path(__file__).resolve().parent / "model_config.json"

# Fields a profile may set. Anything beyond base_url/model/reasoning_effort is
# optional and only overrides the matching CLI default when present.
REQUIRED_PROFILE_FIELDS = ("base_url", "model", "reasoning_effort", "api_key_env")
OPTIONAL_PROFILE_FIELDS = ("api_timeout", "api_max_retries", "api_turn_retries")
OPTIONAL_KEY_FILE_FIELDS = ("api_key_file", "api_key_field")
REASONING_EFFORTS = ("low", "medium", "high", "xhigh")
# reasoning_mode controls whether the Responses request carries a ``reasoning``
# field at all. ``"on"`` (default) sends ``{"effort": <reasoning_effort>}``;
# ``"off"`` sends nothing - for non-thinking models (e.g.
# deepseek-v4-flash-nothinking) where a reasoning param is rejected or ignored.
REASONING_MODES = ("on", "off")


@dataclass(frozen=True)
class ModelProfile:
    name: str
    base_url: str
    model: str
    reasoning_effort: str
    reasoning_mode: str
    api_key_env: str
    api_key_file: str | None
    api_key_field: str | None
    api_timeout: int | None
    api_max_retries: int | None
    api_turn_retries: int | None


def load_model_config() -> dict[str, Any]:
    """Load and structurally validate model_config.json."""
    if not CONFIG_PATH.is_file():
        raise ValueError(f"model config file does not exist: {CONFIG_PATH}")
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid model config JSON: {CONFIG_PATH}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"model config must be a JSON object: {CONFIG_PATH}")
    active_profile = raw.get("active_profile")
    aliases = raw.get("aliases", {})
    profiles = raw.get("profiles")
    if not isinstance(active_profile, str) or not active_profile:
        raise ValueError(f"model config requires non-empty active_profile: {CONFIG_PATH}")
    if not isinstance(aliases, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in aliases.items()
    ):
        raise ValueError(f"model config aliases must map strings to profile names: {CONFIG_PATH}")
    if not isinstance(profiles, dict) or not all(isinstance(k, str) for k in profiles):
        raise ValueError(f"model config requires a profiles object: {CONFIG_PATH}")
    unknown = sorted(set(aliases.values()) - set(profiles))
    if unknown:
        raise ValueError(f"model config aliases reference unknown profiles: {unknown}")
    if active_profile not in profiles:
        raise ValueError(
            f"model config active_profile {active_profile!r} is not in profiles: "
            f"{', '.join(sorted(profiles))}"
        )
    # Aliases and profile names share one namespace: --model-profile accepts
    # either, so a name that is both would be ambiguous. Reject collisions.
    overlap = sorted(set(aliases) & set(profiles))
    if overlap:
        raise ValueError(f"model config names cannot be both a profile and an alias: {overlap}")
    return {"active_profile": active_profile, "aliases": aliases, "profiles": profiles}


def resolve_named_profile_name(requested: str | None = None) -> str:
    """Resolve a profile name or alias, falling back to the active profile.

    This value-oriented helper is shared by the main and verification agents;
    callers do not need to manufacture an ``argparse.Namespace`` merely to
    resolve a secondary model profile.
    """
    raw = load_model_config()
    aliases = raw["aliases"]
    if not requested:
        return raw["active_profile"]
    if requested in aliases:
        return aliases[requested]
    if requested in raw["profiles"]:
        return requested
    available = ", ".join(sorted(set(raw["profiles"]) | set(aliases)))
    raise ValueError(f"unknown model profile or alias {requested!r}; available: {available}")


def resolve_profile_name(args: argparse.Namespace) -> str:
    """Pick the profile name: --model-profile (a name or an alias), else active.

    ``--model-profile`` accepts either a full profile name or one of the short
    ``aliases`` from the config. When the flag is absent, the config's
    ``active_profile`` is used.
    """
    requested = getattr(args, "model_profile", None)
    return resolve_named_profile_name(requested)


def parse_profile(name: str, raw: object) -> ModelProfile:
    if not isinstance(raw, dict):
        raise ValueError(f"model profile {name!r} must be an object")
    missing = [f for f in REQUIRED_PROFILE_FIELDS if not (isinstance(raw.get(f), str) and raw.get(f))]
    if missing:
        raise ValueError(f"model profile {name!r} missing required fields: {missing}")
    effort = raw["reasoning_effort"]
    if effort not in REASONING_EFFORTS:
        raise ValueError(
            f"model profile {name!r}.reasoning_effort must be one of {', '.join(REASONING_EFFORTS)}"
        )
    mode = raw.get("reasoning_mode", "on")
    if mode not in REASONING_MODES:
        raise ValueError(
            f"model profile {name!r}.reasoning_mode must be one of {', '.join(REASONING_MODES)} or absent"
        )

    key_file: str | None = None
    key_field: str | None = None
    for field in OPTIONAL_KEY_FILE_FIELDS:
        value = raw.get(field)
        if value is None:
            continue
        if not isinstance(value, str) or not value:
            raise ValueError(f"model profile {name!r}.{field} must be a non-empty string or absent")
        if field == "api_key_file":
            key_file = value
        else:
            key_field = value
    if bool(key_file) != bool(key_field):
        raise ValueError(
            f"model profile {name!r}: api_key_file and api_key_field must both be set or both absent"
        )

    optional: dict[str, int | None] = {}
    for field in OPTIONAL_PROFILE_FIELDS:
        value = raw.get(field)
        if value is None:
            optional[field] = None
        elif isinstance(value, int) and value >= 0:
            optional[field] = value
        else:
            raise ValueError(f"model profile {name!r}.{field} must be a non-negative int or absent")
    return ModelProfile(
        name=name,
        base_url=raw["base_url"],
        model=raw["model"],
        reasoning_effort=effort,
        reasoning_mode=mode,
        api_key_env=raw["api_key_env"],
        api_key_file=key_file,
        api_key_field=key_field,
        api_timeout=optional["api_timeout"],
        api_max_retries=optional["api_max_retries"],
        api_turn_retries=optional["api_turn_retries"],
    )


def resolve_profile(args: argparse.Namespace) -> ModelProfile:
    return resolve_named_profile(getattr(args, "model_profile", None))


def resolve_named_profile(requested: str | None = None) -> ModelProfile:
    """Return the parsed profile selected by a full name, alias, or default."""
    raw = load_model_config()
    name = resolve_named_profile_name(requested)
    return parse_profile(name, raw["profiles"][name])


def _key_from_file(profile: ModelProfile) -> str:
    path = Path(profile.api_key_file).expanduser()
    if not path.is_file():
        return ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    value = data.get(profile.api_key_field)
    return value if isinstance(value, str) else ""


def reasoning_param(profile: ModelProfile) -> dict[str, Any] | None:
    """The ``reasoning`` field to send on the Responses request, or ``None``.

    ``reasoning_mode == "off"`` -> ``None`` (no field): for non-thinking models
    (e.g. ``deepseek-v4-flash-nothinking``) that reject or ignore a reasoning
    param. ``"on"`` -> ``{"effort": <reasoning_effort>}``.
    """
    if profile.reasoning_mode == "off":
        return None
    return {"effort": profile.reasoning_effort}


def resolve_api_key(profile: ModelProfile) -> str:
    """Resolve the API key: env var named by the profile, else its key file.

    Raises SystemExit (with a clear message) only when the key is genuinely
    unavailable, so ``--dry-run`` callers that set the flag themselves can still
    proceed. Returns "" only when neither source is set; the caller decides
    whether an empty key is fatal (real run) or skippable (dry-run).
    """
    key = os.environ.get(profile.api_key_env, "")
    if key:
        return key
    if profile.api_key_file and profile.api_key_field:
        return _key_from_file(profile)
    return ""


def interactive_env_keys(profile: ModelProfile) -> list[str]:
    """Env var names worth importing from the interactive shell for this profile.

    Only the profile's own key env is requested; importing unrelated shell env
    would re-introduce the old ambient-env behavior the config replaced.
    """
    return [profile.api_key_env]


def apply_profile_to_args(args: argparse.Namespace, profile: ModelProfile) -> None:
    """Apply config profile fields onto args, honoring CLI-overrides-config.

    A CLI flag wins when the user passed it explicitly. We treat empty-string
    defaults as "not set" so a present config field fills them in; for the int
    knobs (timeout/retries), the profile overrides the argparse default whenever
    the profile supplies one (those defaults exist only to make a missing config
    still runnable, so a config value always wins).
    """
    if not args.base_url:
        args.base_url = profile.base_url
    if not args.model:
        args.model = profile.model
    if not args.reasoning_effort:
        args.reasoning_effort = profile.reasoning_effort
    if profile.api_timeout is not None:
        args.api_timeout = profile.api_timeout
    if profile.api_max_retries is not None:
        args.api_max_retries = profile.api_max_retries
    if profile.api_turn_retries is not None:
        args.api_turn_retries = profile.api_turn_retries
