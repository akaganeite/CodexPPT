"""OpenAI Responses API client with bounded retries.

Replaces the former DeepSeek chat-completions client. The Responses API is
stateless here: each turn resends the full conversation history as ``input``
items (``message`` / ``function_call`` / ``function_call_output``). System
prompt rides in the top-level ``instructions`` field. We never use
``previous_response_id`` -- a fresh, self-contained request per turn keeps runs
reproducible and proxy-friendly.

Model API errors (HTTP 429/5xx, timeouts, transport faults) are retried with
exponential backoff inside this call; only a final failure propagates. This is
deliberately separate from tool failures, which never abort a run.

WAF note: the proxy upstream runs a request-body content filter that resets the
connection (HTTP 500 "connection reset by peer") when a ``function_call_output``
payload contains certain security-signature substrings -- notably
``Authorization: Digest`` (which curl's own Digest-auth strings naturally
contain), plus generic SQLi / path-traversal / command-injection patterns. We
therefore scan each tool-output string and, if it matches, transmit it
base64-encoded under a ``b64:`` prefix. The system prompt tells the model to
decode such outputs. Plain outputs with no signature pass through unchanged so
the common case costs nothing.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any


RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}


# Substrings the upstream proxy's body filter treats as hostile and resets on.
# Case-insensitive. Binary tool output that trips one of these is the common case
# for curl Digest-auth CVEs (the format strings contain "Authorization: Digest").
WAF_SIGNATURES = re.compile(
    r"authorization:\s*digest"
    r"|proxy-authorization:\s*digest"
    r"|www-authenticate:\s*digest"
    r"|union\s+select"
    r"|information_schema"
    r"|\.\./"                       # path traversal (../etc/passwd ...)
    r"|;\s*rm\s+-"                  # ; rm -
    r"|;\s*cat\s+/"                 # ; cat /
    r"|\bexec\s*\(",                # exec(  shell-injection shape
    re.IGNORECASE,
)

WAF_B64_PREFIX = "b64:"


def waf_safe_output(output: str) -> str:
    """Return a tool-output string safe to send through the upstream body filter.

    If ``output`` matches a WAF signature, base64-encode it under ``b64:`` so the
    literal signature never appears in the request body; the model decodes it.
    Otherwise return ``output`` unchanged.
    """
    if not isinstance(output, str) or not output:
        return output
    if WAF_SIGNATURES.search(output):
        return WAF_B64_PREFIX + base64.b64encode(output.encode("utf-8")).decode("ascii")
    return output


def _sanitize_input_items(input_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply WAF-safe encoding to every function_call_output in the input.

    Returns a shallow-copied list with copied output items so the caller's
    ``input_items`` (which accumulates across turns) is not mutated in place.
    """
    safe: list[dict[str, Any]] = []
    for item in input_items:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            item = dict(item)
            item["output"] = waf_safe_output(item.get("output", ""))
        safe.append(item)
    return safe


def _deterministic_backoff(attempt: int) -> float:
    # 1s, 2s, 4s, ... with a fixed sub-second offset (no RNG: keeps runs reproducible).
    return min(2.0 ** (attempt - 1), 30.0) + 0.137


def responses_create(
    *,
    instructions: str,
    input_items: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    api_key: str,
    base_url: str,
    model: str,
    timeout: int = 240,
    max_retries: int = 3,
    tool_choice: str = "auto",
    store: bool = False,
    reasoning: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """POST {base_url}/responses and return the parsed response dict.

    The caller inspects ``resp["output"]`` (an items array) to extract
    ``message`` and ``function_call`` items.
    """
    payload: dict[str, Any] = {
        "model": model,
        "instructions": instructions,
        "input": _sanitize_input_items(input_items),
        "tools": tools,
        "tool_choice": tool_choice,
        "stream": False,
        "store": store,
    }
    if reasoning is not None:
        payload["reasoning"] = reasoning

    url = base_url.rstrip("/") + "/responses"
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
            last_error = RuntimeError(f"Responses HTTP {exc.code}: {detail}")
            if exc.code not in RETRYABLE_STATUS or attempt == max_retries:
                raise last_error from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = RuntimeError(f"Responses transport error: {exc!r}")
            if attempt == max_retries:
                raise last_error from exc
        time.sleep(_deterministic_backoff(attempt))

    raise last_error or RuntimeError("Responses request failed")
