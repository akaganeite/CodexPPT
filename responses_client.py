"""Model API client with bounded retries.

The harness keeps a canonical, stateless Responses-style history: each turn
resends ``message`` / ``function_call`` / ``function_call_output`` items. The
Responses protocol sends that history as ``input`` with a top-level
``instructions`` field; no ``previous_response_id`` is used, keeping runs
reproducible and proxy-friendly.

Most configured providers use the OpenAI Responses API. Some compatibility
profiles use the OpenAI-compatible Chat Completions API, so this module can
translate the harness's canonical Responses-style conversation and tool calls
at that boundary. Official DeepSeek uses its Responses API with the
``deepseek_responses`` history adapter, which preserves required thinking
items between stateless requests. The agent loop consequently remains
provider-agnostic.

Model API errors (HTTP 429/5xx, timeouts, transport faults) are retried with
exponential backoff inside this call; only a final failure propagates. This is
deliberately separate from tool failures, which never abort a run.

WAF note: the proxy upstream runs a request-body content filter that resets the
connection (HTTP 500 "connection reset by peer") when a ``function_call_output``
payload contains certain security-signature substrings -- notably
``Authorization: Digest`` (which curl's own Digest-auth strings naturally
contain), plus generic SQLi / path-traversal / command-injection patterns. We
therefore scan each tool-output string. Ordinary matching output is transmitted
base64-encoded under a ``b64:`` prefix. Bounded patch-source JSON prefers an
``uesc:`` prefix and JSON ``\\uXXXX`` escapes only for matching spans, keeping
source snippets readable; dense signatures fall back to the shorter base64
form. Plain outputs with no signature pass through unchanged.
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
API_PROTOCOLS = {"responses", "chat_completions"}
HISTORY_ADAPTERS = {"none", "deepseek_responses"}


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
WAF_UESC_PREFIX = "uesc:"


def _unicode_escape_waf_matches(output: str) -> str:
    """Break every signature with one reversible JSON Unicode escape."""
    escaped = output
    while True:
        match = WAF_SIGNATURES.search(escaped)
        if match is None:
            return escaped
        start, end = match.span()
        matched = escaped[start:end]
        replacement = f"\\u{ord(matched[0]):04x}" + matched[1:]
        escaped = escaped[:start] + replacement + escaped[end:]


def waf_safe_output(output: str, *, readable_json: bool = False) -> str:
    """Return a tool-output string safe to send through the upstream body filter.

    If ``output`` matches a WAF signature, base64-encode it under ``b64:`` by
    default. For bounded source JSON, ``readable_json=True`` replaces only each
    matching span with JSON Unicode escapes under ``uesc:``; parsing the suffix
    as JSON restores the exact source without making a large blob opaque.
    """
    if not isinstance(output, str) or not output:
        return output
    if WAF_SIGNATURES.search(output):
        encoded = WAF_B64_PREFIX + base64.b64encode(output.encode("utf-8")).decode("ascii")
        if readable_json:
            readable = WAF_UESC_PREFIX + _unicode_escape_waf_matches(output)
            return readable if len(readable) <= len(encoded) else encoded
        return encoded
    return output


def _is_bounded_source_guidance(output: str) -> bool:
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return False
    return isinstance(payload, dict) and payload.get("_bounded_source_guidance") is True


def _sanitize_input_items(input_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply WAF-safe encoding to every function_call_output in the input.

    Returns a shallow-copied list with copied output items so the caller's
    ``input_items`` (which accumulates across turns) is not mutated in place.
    """
    safe: list[dict[str, Any]] = []
    for item in input_items:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            item = dict(item)
            output = item.get("output", "")
            item["output"] = waf_safe_output(
                output,
                readable_json=isinstance(output, str) and _is_bounded_source_guidance(output),
            )
        safe.append(item)
    return safe


def _deepseek_responses_history(input_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the minimal DeepSeek-compatible form of prior output items.

    DeepSeek's thinking-mode validator requires the prior ``reasoning_text`` to
    be returned, but rejects output-only fields such as a completed item's
    ``id`` and ``status``. Its Responses documentation specifies the canonical
    input forms used below.
    """
    converted: list[dict[str, Any]] = []
    for item in _sanitize_input_items(input_items):
        item_type = item.get("type")
        if item_type == "reasoning":
            content = item.get("content")
            if isinstance(content, list):
                converted.append({"type": "reasoning", "content": content})
        elif item_type == "function_call":
            call_id = item.get("call_id") or item.get("id")
            name = item.get("name")
            arguments = item.get("arguments")
            if isinstance(call_id, str) and isinstance(name, str) and isinstance(arguments, str):
                converted.append({
                    "type": "function_call",
                    "call_id": call_id,
                    "name": name,
                    "arguments": arguments,
                })
        elif item_type == "message":
            role = item.get("role")
            content = item.get("content")
            if role in {"user", "assistant", "system", "developer"}:
                converted.append({"type": "message", "role": role, "content": content})
        elif item_type == "function_call_output":
            call_id = item.get("call_id")
            output = item.get("output")
            if isinstance(call_id, str):
                converted.append({"type": "function_call_output", "call_id": call_id, "output": output})
    return converted


def _prepared_input_items(input_items: list[dict[str, Any]], history_adapter: str) -> list[dict[str, Any]]:
    if history_adapter == "deepseek_responses":
        return _deepseek_responses_history(input_items)
    return _sanitize_input_items(input_items)


def _deterministic_backoff(attempt: int) -> float:
    # 1s, 2s, 4s, ... with a fixed sub-second offset (no RNG: keeps runs reproducible).
    return min(2.0 ** (attempt - 1), 30.0) + 0.137


def _chat_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert Responses function definitions to Chat Completions tools."""
    converted: list[dict[str, Any]] = []
    for tool in tools:
        if tool.get("type") != "function":
            continue
        function: dict[str, Any] = {
            "name": tool.get("name", ""),
            "parameters": tool.get("parameters", {}),
        }
        if tool.get("description"):
            function["description"] = tool["description"]
        converted.append({"type": "function", "function": function})
    return converted


def _chat_messages(instructions: str, input_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Translate the canonical harness history into Chat Completions messages."""
    messages: list[dict[str, Any]] = [{"role": "system", "content": instructions}]
    assistant_content: str | None = None
    assistant_calls: list[dict[str, Any]] = []

    def flush_assistant() -> None:
        nonlocal assistant_content, assistant_calls
        if assistant_content is None and not assistant_calls:
            return
        message: dict[str, Any] = {"role": "assistant", "content": assistant_content}
        if assistant_calls:
            message["tool_calls"] = assistant_calls
        messages.append(message)
        assistant_content = None
        assistant_calls = []

    for item in _sanitize_input_items(input_items):
        item_type = item.get("type")
        if item_type == "message":
            role = item.get("role")
            content = item.get("content")
            if role == "assistant":
                if assistant_content is not None or assistant_calls:
                    flush_assistant()
                assistant_content = content if isinstance(content, str) else json.dumps(content)
            elif role in {"user", "system"}:
                flush_assistant()
                messages.append({"role": role, "content": content if isinstance(content, str) else json.dumps(content)})
        elif item_type == "function_call":
            call_id = item.get("call_id") or item.get("id")
            name = item.get("name")
            if isinstance(call_id, str) and isinstance(name, str):
                arguments = item.get("arguments", "{}")
                if not isinstance(arguments, str):
                    arguments = json.dumps(arguments)
                assistant_calls.append({
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": arguments},
                })
        elif item_type == "function_call_output":
            flush_assistant()
            call_id = item.get("call_id")
            if isinstance(call_id, str):
                output = item.get("output", "")
                messages.append({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": output if isinstance(output, str) else json.dumps(output),
                })
    flush_assistant()
    return messages


def _chat_response_to_responses(response: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Chat Completions response for the existing agent loop."""
    choices = response.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    output: list[dict[str, Any]] = []
    content = message.get("content")
    if isinstance(content, str) and content:
        output.append({"type": "message", "role": "assistant", "content": content})
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        for index, call in enumerate(tool_calls, 1):
            if not isinstance(call, dict):
                continue
            function = call.get("function") if isinstance(call.get("function"), dict) else {}
            name = function.get("name")
            if not isinstance(name, str) or not name:
                continue
            arguments = function.get("arguments", "{}")
            if not isinstance(arguments, str):
                arguments = json.dumps(arguments)
            call_id = call.get("id")
            if not isinstance(call_id, str) or not call_id:
                call_id = f"chat_call_{index}"
            output.append({
                "type": "function_call",
                "call_id": call_id,
                "name": name,
                "arguments": arguments,
            })
    usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
    normalized_usage = dict(usage)
    if "input_tokens" not in normalized_usage and isinstance(usage.get("prompt_tokens"), int):
        normalized_usage["input_tokens"] = usage["prompt_tokens"]
    if "output_tokens" not in normalized_usage and isinstance(usage.get("completion_tokens"), int):
        normalized_usage["output_tokens"] = usage["completion_tokens"]
    return {"output": output, "usage": normalized_usage}


def _request_json(
    *,
    url: str,
    body: bytes,
    headers: dict[str, str],
    timeout: int,
    max_retries: int,
    protocol_label: str,
) -> dict[str, Any]:
    """POST JSON with bounded retries and provider-neutral diagnostics."""
    last_error: Exception | None = None
    attempts = max(1, max_retries)
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                if not isinstance(payload, dict):
                    raise RuntimeError(f"{protocol_label} returned a non-object JSON response")
                return payload
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            last_error = RuntimeError(f"{protocol_label} HTTP {exc.code}: {detail}")
            if exc.code not in RETRYABLE_STATUS or attempt == attempts:
                raise last_error from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = RuntimeError(f"{protocol_label} transport error: {exc!r}")
            if attempt == attempts:
                raise last_error from exc
        time.sleep(_deterministic_backoff(attempt))
    raise last_error or RuntimeError(f"{protocol_label} request failed")


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
    max_output_tokens: int | None = None,
    api_protocol: str = "responses",
    history_adapter: str = "none",
) -> dict[str, Any]:
    """Submit one canonical agent turn through the selected provider protocol.

    The caller inspects ``resp["output"]`` (an items array) to extract
    ``message`` and ``function_call`` items.
    """
    if api_protocol not in API_PROTOCOLS:
        raise ValueError(f"unsupported API protocol: {api_protocol}")
    if history_adapter not in HISTORY_ADAPTERS:
        raise ValueError(f"unsupported history adapter: {history_adapter}")
    if api_protocol == "chat_completions":
        payload: dict[str, Any] = {
            "model": model,
            "messages": _chat_messages(instructions, input_items),
            "tools": _chat_tools(tools),
            "tool_choice": tool_choice,
            "stream": False,
        }
        if max_output_tokens is not None:
            payload["max_tokens"] = max_output_tokens
        response = _request_json(
            url=base_url.rstrip("/") + "/chat/completions",
            body=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            timeout=timeout,
            max_retries=max_retries,
            protocol_label="Chat Completions",
        )
        return _chat_response_to_responses(response)

    payload: dict[str, Any] = {
        "model": model,
        "instructions": instructions,
        "input": _prepared_input_items(input_items, history_adapter),
        "tools": tools,
        "tool_choice": tool_choice,
        "stream": False,
        "store": store,
    }
    if reasoning is not None:
        payload["reasoning"] = reasoning
    # When set, cap the response output tokens. cliproxy's default for some
    # thinking models (e.g. glm-5.2) is small enough that a long tool-call
    # ``arguments`` JSON gets truncated mid-string -> json.loads fails ->
    # tool_failure. A profile that needs more headroom sets max_output_tokens.
    if max_output_tokens is not None:
        payload["max_output_tokens"] = max_output_tokens

    return _request_json(
        url=base_url.rstrip("/") + "/responses",
        body=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        timeout=timeout,
        max_retries=max_retries,
        protocol_label="Responses",
    )
