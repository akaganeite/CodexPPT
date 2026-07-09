from __future__ import annotations

import argparse
import os


def resolved_model(args: argparse.Namespace) -> str | None:
    if args.model:
        return args.model
    if args.provider == "dpsk":
        return args.dpsk_model
    if args.provider == "pptagent":
        return args.pptagent_model
    if args.provider == "volc":
        return args.volc_model
    return None


def provider_overrides(args: argparse.Namespace) -> list[str]:
    # The "dpsk" provider does not get its own Codex provider entry. Instead we
    # reuse Codex's built-in "OpenAI" provider slot and repoint its base_url at
    # the local DeepSeek-compatible proxy, so the provider name stays "OpenAI"
    # on the wire even though requests actually go to DeepSeek.
    if args.provider != "dpsk":
        if args.provider == "volc":
            return [
                "-c",
                'model_provider="volcengine-agent-plan"',
                "-c",
                (
                    "model_providers.volcengine-agent-plan="
                    f'{{name="volcengine-agent-plan", base_url="{args.volc_base_url}", '
                    f'env_key="{args.volc_api_key_env}", wire_api="responses"}}'
                ),
            ]
        if args.provider != "pptagent":
            return []
        return [
            "-c",
            'model_provider="pptagent-openai"',
            "-c",
            (
                "model_providers.pptagent-openai="
                f'{{name="pptagent-openai", base_url="{args.pptagent_base_url}", '
                f'env_key="{args.pptagent_api_key_env}", wire_api="responses", '
                "requires_openai_auth=false}"
            ),
        ]
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
    if args.provider in {"dpsk", "pptagent", "volc"}:
        bypass_hosts = ["127.0.0.1", "localhost"]
        if args.provider == "pptagent":
            bypass_hosts.append("192.168.104.61")
        for key in ("NO_PROXY", "no_proxy"):
            existing = env.get(key, "")
            parts = [part.strip() for part in existing.split(",") if part.strip()]
            for host in bypass_hosts:
                if host not in parts:
                    parts.append(host)
            env[key] = ",".join(parts)
    return env
