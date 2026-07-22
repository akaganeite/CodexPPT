"""Tests for model_config profile parsing and reasoning_param.

    python3 -m claudeagent.tests.test_model_config

Offline: exercises parse_profile + reasoning_param with synthetic profiles so
the reasoning on/off decision (critical for non-thinking models like
deepseek-v4-flash-nothinking) does not regress. Also confirms the shipped
model_config.json loads and its cliproxy_deepseek_v4_flash profile is mode=off.
"""

from __future__ import annotations

import argparse
import sys

from claudeagent.model_config import (
    ModelProfile,
    parse_profile,
    reasoning_param,
    resolve_profile,
)


def _profile(*, mode="on", effort="low") -> ModelProfile:
    return ModelProfile(
        name="t",
        base_url="http://x/v1",
        model="m",
        reasoning_effort=effort,
        reasoning_mode=mode,
        api_key_env="K",
        api_key_file=None,
        api_key_field=None,
        api_timeout=None,
        api_max_retries=None,
        api_turn_retries=None,
    )


def _run() -> int:
    failures: list[str] = []

    def check(label: str, cond: bool) -> None:
        if not cond:
            failures.append(label)

    # 1. mode=on -> sends {"effort": <effort>}.
    check("on sends effort dict", reasoning_param(_profile(mode="on", effort="high")) == {"effort": "high"})

    # 2. mode=off -> None (no reasoning field on the wire). effort is still
    #    carried by the profile for schema validity but never sent.
    check("off sends None", reasoning_param(_profile(mode="off", effort="high")) is None)

    # 3. parse_profile defaults reasoning_mode to "on" when absent.
    parsed = parse_profile("p", {
        "base_url": "http://x/v1", "model": "m",
        "reasoning_effort": "low", "api_key_env": "K",
    })
    check("default mode on", parsed.reasoning_mode == "on")
    check("default on sends effort", reasoning_param(parsed) == {"effort": "low"})

    # 4. parse_profile honors an explicit reasoning_mode: "off".
    parsed_off = parse_profile("p", {
        "base_url": "http://x/v1", "model": "m",
        "reasoning_effort": "high", "reasoning_mode": "off", "api_key_env": "K",
    })
    check("explicit mode off", parsed_off.reasoning_mode == "off")
    check("explicit off sends None", reasoning_param(parsed_off) is None)

    # 5. parse_profile rejects an invalid reasoning_mode.
    try:
        parse_profile("p", {
            "base_url": "http://x/v1", "model": "m",
            "reasoning_effort": "low", "reasoning_mode": "bogus", "api_key_env": "K",
        })
        check("reject bad mode", False)
    except ValueError:
        check("reject bad mode", True)

    # 6. The shipped config's deepseek profile is mode=off (non-thinking model).
    a = argparse.Namespace(model_profile="deepseek")
    shipped = resolve_profile(a)
    check("shipped deepseek name", shipped.name == "cliproxy_deepseek_v4_flash")
    check("shipped deepseek mode off", shipped.reasoning_mode == "off")
    check("shipped deepseek no reasoning", reasoning_param(shipped) is None)

    # 7. The shipped default profile stays mode=on (regression guard for gpt-5.5).
    a2 = argparse.Namespace(model_profile="")
    default = resolve_profile(a2)
    check("shipped default mode on", default.reasoning_mode == "on")
    check("shipped default sends effort", reasoning_param(default) == {"effort": default.reasoning_effort})

    if failures:
        print("FAIL:", failures)
        return 1
    print("MODEL CONFIG TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
