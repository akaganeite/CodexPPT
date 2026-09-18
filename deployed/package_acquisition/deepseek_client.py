"""Minimal official DeepSeek chat-completions client used by package ranking."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_LLM_CONFIG = Path(__file__).resolve().parents[1] / "llm_config.json"


@dataclass(frozen=True)
class DeepSeekConfig:
    enabled: bool
    provider: str
    base_url: str
    endpoint: str
    model: str
    api_key: str
    api_key_env: str
    timeout_seconds: int
    max_retries: int
    temperature: float
    max_tokens: int
    json_mode: bool

    @property
    def url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.endpoint.lstrip('/')}"

    def resolved_api_key(self) -> tuple[str, str]:
        if self.api_key.strip():
            return self.api_key.strip(), "config"
        value = os.environ.get(self.api_key_env.strip(), "").strip() if self.api_key_env.strip() else ""
        return (value, f"env:{self.api_key_env.strip()}") if value else ("", "missing")

    def public_json(self) -> dict[str, Any]:
        _, key_source = self.resolved_api_key()
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "base_url": self.base_url,
            "endpoint": self.endpoint,
            "model": self.model,
            "api_key_source": key_source,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "json_mode": self.json_mode,
        }


def load_llm_config(path: Path | None = None) -> DeepSeekConfig:
    raw = json.loads((path or DEFAULT_LLM_CONFIG).expanduser().resolve().read_text(encoding="utf-8"))
    return DeepSeekConfig(
        enabled=bool(raw.get("enabled", True)),
        provider=str(raw.get("provider") or "deepseek"),
        base_url=str(raw.get("base_url") or "https://api.deepseek.com"),
        endpoint=str(raw.get("endpoint") or "/chat/completions"),
        model=str(raw.get("model") or "deepseek-v4-pro"),
        api_key=str(raw.get("api_key") or ""),
        api_key_env=str(raw.get("api_key_env") or "DEEPSEEK_API_KEY"),
        timeout_seconds=max(1, int(raw.get("timeout_seconds", 300))),
        max_retries=max(0, int(raw.get("max_retries", 2))),
        temperature=float(raw.get("temperature", 0.0)),
        max_tokens=max(1, int(raw.get("max_tokens", 4096))),
        json_mode=bool(raw.get("json_mode", True)),
    )


def call_deepseek(config: DeepSeekConfig, api_key: str, prompt: str) -> tuple[dict[str, Any], dict[str, Any]]:
    payload: dict[str, Any] = {
        "model": config.model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an Ubuntu and Debian binary-packaging expert. Rank only candidate IDs supplied by the user. "
                    "Never invent package names or candidate IDs. Return one JSON object."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
    }
    if config.json_mode:
        payload["response_format"] = {"type": "json_object"}
    request = urllib.request.Request(
        config.url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "agentic-dataset-deployed-builder/1.0",
        },
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(config.max_retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
            choices = body.get("choices") or []
            message = choices[0].get("message") if choices and isinstance(choices[0], dict) else {}
            parsed = parse_json_object(str((message or {}).get("content") or ""))
            return parsed, {
                "id": body.get("id") or "",
                "model": body.get("model") or config.model,
                "usage": body.get("usage") or {},
                "finish_reason": choices[0].get("finish_reason") if choices and isinstance(choices[0], dict) else "",
            }
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[-2000:]
            last_error = RuntimeError(f"DeepSeek HTTP {exc.code}: {detail}")
            if exc.code not in {408, 409, 429, 500, 502, 503, 504}:
                break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            last_error = exc
        if attempt < config.max_retries:
            time.sleep(2**attempt)
    raise RuntimeError(f"DeepSeek package ranking failed: {last_error}")


def parse_json_object(value: str) -> dict[str, Any]:
    text = value.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1).strip()
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("DeepSeek response is not a JSON object")
    return parsed
