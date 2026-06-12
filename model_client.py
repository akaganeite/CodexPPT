"""DeepSeek (OpenAI-compatible) chat-completions client with bounded retries.

Model API errors (HTTP 429/5xx, timeouts, transport faults) are retried with
exponential backoff inside this call; only a final failure propagates. This is
deliberately separate from tool failures, which never abort a run.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any


RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}


def _deterministic_backoff(attempt: int) -> float:
    # 1s, 2s, 4s, ... with a fixed sub-second offset (no RNG: keeps runs reproducible).
    return min(2.0 ** (attempt - 1), 30.0) + 0.137


def deepseek_chat(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    *,
    api_key: str,
    base_url: str,
    model: str,
    thinking: bool,
    reasoning_effort: str,
    timeout: int,
    max_retries: int = 3,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "stream": False,
    }
    if thinking:
        payload["thinking"] = {"type": "enabled"}
        payload["reasoning_effort"] = reasoning_effort
    elif "deepseek" in model:
        payload["thinking"] = {"type": "disabled"}

    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}

    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            last_error = RuntimeError(f"DeepSeek HTTP {exc.code}: {detail}")
            if exc.code not in RETRYABLE_STATUS or attempt == max_retries:
                raise last_error from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = RuntimeError(f"DeepSeek transport error: {exc!r}")
            if attempt == max_retries:
                raise last_error from exc
        time.sleep(_deterministic_backoff(attempt))

    raise last_error or RuntimeError("DeepSeek request failed")
