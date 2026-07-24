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
    resolve_named_profile,
    resolve_named_profile_name,
    resolve_profile,
)
from claudeagent.verify_config import (
    expected_verify_agent_signature,
    resolve_verify_agent_settings,
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

    # 8. Secondary agents can resolve a name or alias without constructing an
    #    argparse namespace.
    check("value resolver accepts alias", resolve_named_profile_name("deepseek") == "cliproxy_deepseek_v4_flash")
    check("value resolver returns profile", resolve_named_profile("deepseek").name == "cliproxy_deepseek_v4_flash")

    # 9. An inherited verifier uses effective main provider overrides while
    #    retaining the main profile's reasoning semantics.
    inherited_args = argparse.Namespace(
        model_profile="",
        model="override-model",
        base_url="http://override/v1",
        api_timeout=321,
        api_max_retries=4,
        api_turn_retries=2,
        verify_model_profile="",
        verify_verdict_calls=4,
        no_strict=False,
        verify_agent="on",
    )
    inherited = resolve_verify_agent_settings(
        inherited_args,
        main_profile=_profile(mode="on", effort="high"),
    )
    check("inherited verifier uses main model override", inherited.config.model == "override-model")
    check("inherited verifier uses main base URL override", inherited.config.base_url == "http://override/v1")
    check("inherited verifier keeps profile reasoning", inherited.config.reasoning == {"effort": "high"})
    check("inherited verifier uses effective API knobs", (
        inherited.config.api_timeout,
        inherited.config.api_max_retries,
        inherited.config.api_turn_retries,
    ) == (321, 4, 2))
    check("inherited verifier carries requested budget", inherited.config.verdict_calls == 4)
    check("digest placeholder has no API key", inherited.config.api_key == "" and len(inherited.config_digest) == 64)

    # 10. An explicit verifier profile ignores main provider overrides.
    explicit_args = argparse.Namespace(**{
        **vars(inherited_args),
        "verify_model_profile": "deepseek",
    })
    explicit = resolve_verify_agent_settings(explicit_args, main_profile=_profile())
    check("explicit verifier alias canonicalized", explicit.profile_name == "cliproxy_deepseek_v4_flash")
    check("explicit verifier ignores main model override", explicit.config.model == "deepseek-v4-flash-nothinking")
    check("explicit verifier ignores main URL override", explicit.config.base_url == "http://127.0.0.1:8317/v1")
    check("explicit verifier reasoning mode honored", explicit.config.reasoning is None)

    # 11. Off mode has a stable empty resume digest and does not require a
    #     verifier profile or API key.
    off_args = argparse.Namespace(**{
        **vars(inherited_args),
        "verify_agent": "off",
        "verify_model_profile": "does-not-need-resolution",
    })
    check("off verifier resume signature", expected_verify_agent_signature(off_args) == ("off", ""))

    if failures:
        print("FAIL:", failures)
        return 1
    print("MODEL CONFIG TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
