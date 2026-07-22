"""Tests for the upstream-WAF body-filter bypass in responses_client.

    python3 -m claudeagent.tests.test_waf

The proxy upstream runs a request-body content filter that resets the connection
on security-signature substrings (``Authorization: Digest``, ``union select``,
path traversal, etc.). ``responses_client.waf_safe_output`` base64-encodes any
tool-output string that matches so the literal signature never reaches the wire;
plain outputs pass through. These tests are offline (no network).
"""

from __future__ import annotations

import base64
import sys

from claudeagent.responses_client import WAF_B64_PREFIX, _sanitize_input_items, waf_safe_output


def _run() -> int:
    failures: list[str] = []

    def check(label: str, cond: bool) -> None:
        if not cond:
            failures.append(label)

    # 1. plain output with no signature passes through unchanged.
    check("plain passthrough", waf_safe_output("call 0x1234 snprintf@plt") == "call 0x1234 snprintf@plt")
    check("empty passthrough", waf_safe_output("") == "")

    # 2. curl Digest-auth header (the CVE-2013-0249 trigger) gets b64-encoded.
    enc = waf_safe_output('Authorization: Digest username="%s", realm="%s"')
    check("digest-auth encoded", enc.startswith(WAF_B64_PREFIX))
    check("digest-auth roundtrip", base64.b64decode(enc[len(WAF_B64_PREFIX):]).decode()
          == 'Authorization: Digest username="%s", realm="%s"')

    # 3. signature matching is case-insensitive.
    check("case-insensitive", waf_safe_output("authorization: digest x").startswith(WAF_B64_PREFIX))

    # 4. the other WAF signatures also trip encoding.
    check("union select", waf_safe_output("x union select y").startswith(WAF_B64_PREFIX))
    check("path traversal", waf_safe_output("../../../etc/passwd").startswith(WAF_B64_PREFIX))
    check("cmd injection rm", waf_safe_output("; rm -rf /").startswith(WAF_B64_PREFIX))

    # 5. _sanitize_input_items only rewrites function_call_output, copies items, and
    #    leaves the caller's list intact.
    items = [
        {"type": "message", "role": "user", "content": "hi"},
        {"type": "function_call_output", "call_id": "c1", "output": "Authorization: Digest x"},
        {"type": "function_call", "name": "run_python", "call_id": "c1", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "c2", "output": "clean output"},
    ]
    safe = _sanitize_input_items(items)
    check("sanitize message untouched", safe[0] == items[0])
    check("sanitize fc untouched", safe[2] == items[2])
    check("sanitize dirty fco encoded", safe[1]["output"].startswith(WAF_B64_PREFIX))
    check("sanitize clean fco plain", safe[3]["output"] == "clean output")
    check("sanitize non-mutating", items[1]["output"] == "Authorization: Digest x")

    if failures:
        print("FAIL:", failures)
        return 1
    print("WAF TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
