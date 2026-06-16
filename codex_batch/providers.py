from __future__ import annotations

import argparse
import os


def resolved_model(args: argparse.Namespace) -> str | None:
    if args.model:
        return args.model
    if args.provider == "dpsk":
        return args.dpsk_model
    return None


def provider_overrides(args: argparse.Namespace) -> list[str]:
    # The "dpsk" provider does not get its own Codex provider entry. Instead we
    # reuse Codex's built-in "OpenAI" provider slot and repoint its base_url at
    # the local DeepSeek-compatible proxy, so the provider name stays "OpenAI"
    # on the wire even though requests actually go to DeepSeek.
    if args.provider != "dpsk":
        return []
    return [
        "-c",
        'model_provider="OpenAI"',
        "-c",
        f'model_providers.OpenAI.base_url="{args.dpsk_base_url}"',
        "-c",
        'model_providers.OpenAI.wire_api="responses"',
        "-c",
        "model_providers.OpenAI.requires_openai_auth=true",
    ]


def codex_env(args: argparse.Namespace) -> dict[str, str]:
    env = os.environ.copy()
    if args.provider == "dpsk":
        bypass_hosts = ["127.0.0.1", "localhost"]
        for key in ("NO_PROXY", "no_proxy"):
            existing = env.get(key, "")
            parts = [part.strip() for part in existing.split(",") if part.strip()]
            for host in bypass_hosts:
                if host not in parts:
                    parts.append(host)
            env[key] = ",".join(parts)
    return env
