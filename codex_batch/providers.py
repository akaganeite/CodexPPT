from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


MODEL_CONFIG_PATH = Path(__file__).resolve().parent.parent / "model_config.json"
REASONING_EFFORTS = {"low", "medium", "high", "xhigh"}


@dataclass(frozen=True)
class ModelProfile:
    name: str
    provider: str
    base_url: str | None
    wire_api: str | None
    model: str | None
    api_key_env: str | None
    requires_openai_auth: bool
    reasoning_mode: str
    reasoning_effort: str | None
    codex_provider_name: str

    @property
    def uses_current_codex_provider(self) -> bool:
        return self.provider == "codex"

def resolve_profile(args: argparse.Namespace) -> ModelProfile:
    raw = load_model_config()
    profiles = raw["profiles"]
    profile_name = args.model_profile
    if args.provider:
        aliases = raw["aliases"]
        try:
            profile_name = aliases[args.provider]
        except KeyError as exc:
            available = ", ".join(sorted(aliases))
            raise ValueError(f"unknown provider alias {args.provider!r}; available aliases: {available}") from exc
    if profile_name is None:
        profile_name = raw["active_profile"]
    if profile_name not in profiles:
        available = ", ".join(sorted(profiles))
        raise ValueError(f"unknown model profile {profile_name!r}; available profiles: {available}")
    return parse_profile(profile_name, profiles[profile_name])


def load_model_config() -> dict[str, object]:
    if not MODEL_CONFIG_PATH.is_file():
        raise ValueError(f"model config file does not exist: {MODEL_CONFIG_PATH}")
    try:
        raw = json.loads(MODEL_CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid model config JSON: {MODEL_CONFIG_PATH}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"model config must be a JSON object: {MODEL_CONFIG_PATH}")
    active_profile = raw.get("active_profile")
    aliases = raw.get("aliases", {})
    profiles = raw.get("profiles")
    if not isinstance(active_profile, str) or not active_profile:
        raise ValueError(f"model config requires non-empty active_profile: {MODEL_CONFIG_PATH}")
    if not isinstance(aliases, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in aliases.items()
    ):
        raise ValueError(f"model config aliases must map strings to profile names: {MODEL_CONFIG_PATH}")
    if not isinstance(profiles, dict) or not all(isinstance(key, str) for key in profiles):
        raise ValueError(f"model config requires a profiles object: {MODEL_CONFIG_PATH}")
    unknown_alias_targets = sorted(set(aliases.values()) - set(profiles))
    if unknown_alias_targets:
        raise ValueError(f"model config aliases reference unknown profiles: {unknown_alias_targets}")
    return {"active_profile": active_profile, "aliases": aliases, "profiles": profiles}


def parse_profile(name: str, raw: object) -> ModelProfile:
    if not isinstance(raw, dict):
        raise ValueError(f"model profile {name!r} must be an object")
    provider = raw.get("provider")
    if not isinstance(provider, str) or not provider:
        raise ValueError(f"model profile {name!r} requires a non-empty provider")

    reasoning = raw.get("reasoning", {"mode": "inherit"})
    if not isinstance(reasoning, dict):
        raise ValueError(f"model profile {name!r}.reasoning must be an object")
    reasoning_mode = reasoning.get("mode", "inherit")
    if reasoning_mode not in {"on", "off", "inherit"}:
        raise ValueError(f"model profile {name!r}.reasoning.mode must be on, off, or inherit")
    reasoning_effort = reasoning.get("effort")
    if reasoning_mode == "on":
        if reasoning_effort not in REASONING_EFFORTS:
            raise ValueError(
                f"model profile {name!r}.reasoning.effort must be one of "
                f"{', '.join(sorted(REASONING_EFFORTS))} when reasoning is on"
            )
    elif reasoning_effort is not None and reasoning_effort not in REASONING_EFFORTS:
        raise ValueError(f"model profile {name!r}.reasoning.effort is invalid")

    if provider == "codex":
        return ModelProfile(
            name=name,
            provider=provider,
            base_url=None,
            wire_api=None,
            model=None,
            api_key_env=None,
            requires_openai_auth=False,
            reasoning_mode=reasoning_mode,
            reasoning_effort=reasoning_effort,
            codex_provider_name="",
        )

    base_url = raw.get("base_url")
    wire_api = raw.get("wire_api")
    model = raw.get("model")
    if not all(isinstance(value, str) and value for value in (base_url, wire_api, model)):
        raise ValueError(
            f"model profile {name!r} requires non-empty base_url, wire_api, and model"
        )
    api_key_env = first_api_key_env(raw.get("api_key_env"), name)
    requires_openai_auth = raw.get("requires_openai_auth", False)
    if not isinstance(requires_openai_auth, bool):
        raise ValueError(f"model profile {name!r}.requires_openai_auth must be boolean")
    if not requires_openai_auth and api_key_env is None:
        raise ValueError(
            f"model profile {name!r} requires api_key_env unless requires_openai_auth is true"
        )
    codex_provider_name = raw.get("codex_provider_name")
    if codex_provider_name is None:
        codex_provider_name = "straight-detect-" + re.sub(r"[^A-Za-z0-9_-]+", "-", name)
    if not isinstance(codex_provider_name, str) or not codex_provider_name:
        raise ValueError(f"model profile {name!r}.codex_provider_name must be a non-empty string")
    return ModelProfile(
        name=name,
        provider=provider,
        base_url=base_url,
        wire_api=wire_api,
        model=model,
        api_key_env=api_key_env,
        requires_openai_auth=requires_openai_auth,
        reasoning_mode=reasoning_mode,
        reasoning_effort=reasoning_effort,
        codex_provider_name=codex_provider_name,
    )


def first_api_key_env(value: object, profile_name: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value:
        return value
    if isinstance(value, list) and value and isinstance(value[0], str) and value[0]:
        if not all(isinstance(item, str) and item for item in value):
            raise ValueError(f"model profile {profile_name!r}.api_key_env must contain strings")
        return value[0]
    raise ValueError(f"model profile {profile_name!r}.api_key_env must be a string or string list")


def provider_overrides(profile: ModelProfile) -> list[str]:
    if profile.uses_current_codex_provider:
        return []
    assert profile.base_url is not None
    assert profile.wire_api is not None
    assert profile.api_key_env is not None or profile.requires_openai_auth
    fields = [
        f'name="{profile.codex_provider_name}"',
        f'base_url="{profile.base_url}"',
    ]
    if profile.api_key_env is not None:
        fields.append(f'env_key="{profile.api_key_env}"')
    fields.extend(
        [
            f'wire_api="{profile.wire_api}"',
            f'requires_openai_auth={str(profile.requires_openai_auth).lower()}',
        ]
    )
    return [
        "-c",
        f'model_provider="{profile.codex_provider_name}"',
        "-c",
        f'model_providers.{profile.codex_provider_name}={{' + ", ".join(fields) + "}",
    ]


def resolved_reasoning_effort(args: argparse.Namespace, profile: ModelProfile) -> str | None:
    if args.reasoning_effort:
        return args.reasoning_effort
    if profile.reasoning_mode == "on":
        return profile.reasoning_effort
    return None


def codex_env(profile: ModelProfile) -> dict[str, str]:
    env = os.environ.copy()
    if profile.uses_current_codex_provider or profile.base_url is None:
        return env
    host = urlparse(profile.base_url).hostname
    for key in ("NO_PROXY", "no_proxy"):
        parts = [part.strip() for part in env.get(key, "").split(",") if part.strip()]
        for bypass_host in ("127.0.0.1", "localhost", host):
            if bypass_host and bypass_host not in parts:
                parts.append(bypass_host)
        env[key] = ",".join(parts)
    return env
