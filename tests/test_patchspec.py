"""Offline tests for deterministic/model-assisted PatchSpec v1.

Run from the package parent:
    python3 -m claudeagent.tests.test_patchspec
"""

from __future__ import annotations

import copy
import contextlib
import io
import json
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from claudeagent.patchspec import (
    PatchSpecModelConfig,
    PatchSpecValidationError,
    build_deterministic_skeleton,
    ensure_patch_spec,
    generate_patch_spec,
    metadata_sha256,
    model_input_view,
    patch_spec_cache_path,
    patch_spec_digest,
    prompt_view,
    resolve_source_excerpts,
    validate_patch_spec,
)
from claudeagent.patchspec.__main__ import main as patchspec_main


METADATA = {
    "cve_id": "CVE-2013-1944",
    "project": "curl",
    "cwe": "CWE-200",
    "functions": ["tailmatch"],
    "patch_commit_message": "SECRET COMMIT TEXT MUST NOT ENTER MODEL INPUT",
    "binary_path": "/forbidden/target_binary",
    "groundtruth": "present",
    "reduced_function_code": [
        {
            "tailmatch": "if(path starts ../) reject_parent_traversal();",
            "groundtruth": "REDUCED-CODE SECRET",
            "binary_path": "/another/forbidden/binary",
        }
    ],
    "patch_hunk": [
        {
            "header": "@@ -118,15 +118,29 @@ static void freecookie(struct Cookie *co)",
            "old_lines": [
                "static bool tailmatch(const char *little, const char *bigone)",
                "  size_t littlelen = strlen(little);",
                "  size_t biglen = strlen(bigone);",
                "  if(littlelen > biglen)",
                "  return Curl_raw_equal(little, bigone+biglen-littlelen) ? TRUE : FALSE;",
            ],
            "new_lines": [
                "static bool tailmatch(const char *cooke_domain, const char *hostname)",
                "  size_t cookie_domain_len = strlen(cooke_domain);",
                "  size_t hostname_len = strlen(hostname);",
                "  if(hostname_len < cookie_domain_len)",
                "  if(!Curl_raw_equal(cooke_domain, hostname+hostname_len-cookie_domain_len))",
                "    return FALSE;",
                "",
                "  /* label-boundary explanation only */",
                "  if(hostname_len == cookie_domain_len)",
                "    return TRUE;",
                "  if('.' == *(hostname + hostname_len - cookie_domain_len - 1))",
                "    return TRUE;",
                "  return FALSE;",
            ],
        }
    ],
    "patch_intent_analysis": {
        "intended_security_property": "Only exact domains or dot-delimited subdomains match.",
        "summary": "Require an exact match or a dot before the suffix.",
    },
    "root_cause_analysis": {
        "summary": "Suffix-only matching crosses domain boundaries.",
        "unsafe_mechanism": "The old comparison accepts any hostname suffix.",
        "groundtruth": "NESTED SECRET",
    },
    "vulnerability_description": "curl before 7.30.0 can leak cookies during domain matching.",
}


CONFIG = PatchSpecModelConfig(
    api_key="test-key",
    base_url="https://example.invalid/v1",
    model="gpt-5.5",
    reasoning_effort="medium",
    reasoning={"effort": "medium"},
    timeout=1,
    max_retries=1,
)


VALID_DRAFT = {
    "security_invariant": "A suffix match must end at a DNS label boundary.",
    "behaviors": [
        {
            "hunk_ids": ["H001"],
            "old_indicator_refs": ["/patch_hunk/0/old_lines/4"],
            "new_indicator_refs": [
                "/patch_hunk/0/new_lines/8",
                "/patch_hunk/0/new_lines/10",
                "/patch_hunk/0/new_lines/12",
            ],
            "old_semantics": "A suffix equality result directly decides the match.",
            "new_semantics": "The code also requires exact length or a preceding dot.",
            "compiler_equivalent_forms": ["Equivalent compare-and-branch ordering."],
            "applicability": ["A cookie domain matching implementation is present."],
        }
    ],
}


def _response(draft, usage=None):
    return {
        "output": [
            {
                "type": "function_call",
                "call_id": "call_patchspec",
                "name": "submit_patch_spec",
                "arguments": json.dumps(draft),
            }
        ],
        "usage": usage or {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
    }


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    # Deterministic hash, IDs, trusted/advisory layout, and real CVE anchors.
    reordered = dict(reversed(list(METADATA.items())))
    check("metadata hash stable", metadata_sha256(METADATA) == metadata_sha256(reordered))
    skeleton = build_deterministic_skeleton(
        METADATA,
        model=CONFIG.model,
        reasoning_effort=CONFIG.reasoning_effort,
        reasoning=CONFIG.reasoning,
    )
    check("stable hunk id", skeleton["hunks"][0]["hunk_id"] == "H001")
    check("stable behavior id", skeleton["behaviors"][0]["behavior_id"] == "B001")
    check("double layer", set(skeleton["behaviors"][0]) >= {"trusted", "advisory"})
    anchors = {(item["kind"], item["value"]): item for item in skeleton["anchors"]}
    check("function anchor", ("function", "tailmatch") in anchors)
    check("callee anchor", ("callee", "Curl_raw_equal") in anchors)
    check("anchors are localization only", all(item.get("role") == "localization" for item in skeleton["anchors"]))
    dot = anchors.get(("character_constant", "."), {})
    check("dot canonical", dot.get("canonical_value") == "0x2e")
    check("prompt strips generation", "generation" not in prompt_view(skeleton))
    excerpts = resolve_source_excerpts(METADATA, skeleton)
    check("source excerpts sorted", excerpts == sorted(excerpts, key=lambda item: item["ref"]))
    check("source excerpts leaf", all(not isinstance(item["value"], (dict, list)) for item in excerpts))
    investigation_payload = json.dumps(
        {"patch_spec": prompt_view(skeleton), "source_excerpts": excerpts},
        ensure_ascii=False,
    )
    check("investigation view omits commit", "SECRET COMMIT" not in investigation_payload)
    check("investigation view omits groundtruth", "NESTED SECRET" not in investigation_payload)

    with_noop_hunk = copy.deepcopy(METADATA)
    with_noop_hunk["patch_hunk"].append({
        "header": "@@ whitespace only @@",
        "old_lines": [""],
        "new_lines": ["  "],
    })
    noop_spec = build_deterministic_skeleton(
        with_noop_hunk,
        model=CONFIG.model,
        reasoning_effort=CONFIG.reasoning_effort,
        reasoning=CONFIG.reasoning,
    )
    check("ignore whitespace-only hunk", [item["hunk_id"] for item in noop_spec["hunks"]] == ["H001"])

    # Grounding rejects invented anchors, invalid refs, and side crossing.
    invented = copy.deepcopy(skeleton)
    invented["anchors"][0]["value"] = "invented_function"
    check("reject invented anchor", any("ungrounded anchors" in item for item in validate_patch_spec(invented, METADATA)))
    bad_ref = copy.deepcopy(skeleton)
    bad_ref["behaviors"][0]["trusted"]["new_indicators"][0]["ref"] = "/patch_hunk/0/new_lines/999"
    check("reject invalid ref", bool(validate_patch_spec(bad_ref, METADATA)))
    crossed = copy.deepcopy(skeleton)
    old_indicator = crossed["behaviors"][0]["trusted"]["old_indicators"][0]
    crossed["behaviors"][0]["trusted"]["new_indicators"] = [copy.deepcopy(old_indicator)]
    check("reject wrong side", any("new-side" in item for item in validate_patch_spec(crossed, METADATA)))
    same_text = copy.deepcopy(skeleton)
    same_text["behaviors"][0]["trusted"]["new_indicators"][0]["value"] = old_indicator["value"]
    check(
        "reject identical pseudo discriminator",
        any("identical old/new indicators" in item for item in validate_patch_spec(same_text, METADATA)),
    )
    leaky_advisory = copy.deepcopy(skeleton)
    leaky_advisory["behaviors"][0]["advisory"]["applicability"] = [
        "Applies to curl before 7.30.0 from /home/user/build."
    ]
    check(
        "reject advisory version/path leak",
        any("must not contain release versions" in item for item in validate_patch_spec(leaky_advisory, METADATA)),
    )

    reordered_metadata = {
        "cve_id": "CVE-ORDER",
        "project": "curl",
        "functions": ["ordered"],
        "patch_hunk": [{
            "old_lines": ["first();", "second();"],
            "new_lines": ["second();", "first();"],
        }],
    }
    reordered = build_deterministic_skeleton(
        reordered_metadata,
        model=CONFIG.model,
        reasoning_effort=CONFIG.reasoning_effort,
        reasoning=CONFIG.reasoning,
        mode="degraded",
    )
    reordered_kinds = {
        item["kind"]
        for side in ("old_indicators", "new_indicators")
        for item in reordered["behaviors"][0]["trusted"][side]
    }
    check("reorder fallback uses source sequences", reordered_kinds == {"source_sequence"})
    check("reorder fallback valid", not validate_patch_spec(reordered, reordered_metadata))
    check(
        "reorder excerpts preserve sequences",
        all(isinstance(item["value"], list) for item in resolve_source_excerpts(reordered_metadata, reordered)),
    )

    multi_hunk_metadata = copy.deepcopy(METADATA)
    multi_hunk_metadata["patch_hunk"].append({
        "header": "@@ second security-relevant hunk @@",
        "old_lines": ["  return old_check(value);"],
        "new_lines": ["  return new_check(value);"],
    })
    incomplete_multi_hunk = build_deterministic_skeleton(
        multi_hunk_metadata,
        model=CONFIG.model,
        reasoning_effort=CONFIG.reasoning_effort,
        reasoning=CONFIG.reasoning,
    )
    incomplete_multi_hunk["behaviors"][0]["hunk_ids"].append("H002")
    incomplete_multi_hunk["behaviors"] = [incomplete_multi_hunk["behaviors"][0]]
    check(
        "reject multi-hunk behavior missing per-hunk indicators",
        any(
            "must select a grounded indicator for H002" in item
            for item in validate_patch_spec(incomplete_multi_hunk, multi_hunk_metadata)
        ),
    )

    # One-shot model generation never sees forbidden/raw metadata fields.
    calls: list[dict] = []

    def valid_client(**kwargs):
        calls.append(kwargs)
        return _response(VALID_DRAFT)

    generated = generate_patch_spec(METADATA, config=CONFIG, client=valid_client)
    check("generated mode", generated.generation_mode == "generated")
    check("one generation call", len(calls) == 1)
    sent = json.dumps(calls[0]["input_items"], ensure_ascii=False)
    check("no commit message", "SECRET COMMIT" not in sent and "patch_commit_message" not in sent)
    check("no binary", "/forbidden/target_binary" not in sent and "binary_path" not in sent)
    check("no groundtruth", '"groundtruth"' not in sent and '"present"' not in sent)
    check("no nested secret", "NESTED SECRET" not in sent)
    check("no reduced-code secret", "REDUCED-CODE SECRET" not in sent)
    check("no release range", "7.30.0" not in sent)
    check("WAF-sensitive source encoded", "../" not in sent and "b64:" in sent)
    check("generated valid", not validate_patch_spec(generated.spec, METADATA))

    # Invalid first submission gets exactly one repair.
    repair_calls = 0

    def repair_client(**kwargs):
        nonlocal repair_calls
        repair_calls += 1
        if repair_calls == 1:
            invalid = copy.deepcopy(VALID_DRAFT)
            invalid["behaviors"][0]["new_indicator_refs"] = ["/patch_hunk/0/old_lines/4"]
            return _response(invalid, {
                "input_tokens": 3,
                "output_tokens": 1,
                "total_tokens": 4,
                "input_tokens_details": {"cached_tokens": 1},
                "output_tokens_details": {"reasoning_tokens": 2},
            })
        return _response(VALID_DRAFT, {
            "input_tokens": 4,
            "output_tokens": 2,
            "total_tokens": 6,
            "input_tokens_details": {"cached_tokens": 4},
            "output_tokens_details": {"reasoning_tokens": 3},
        })

    repaired = generate_patch_spec(METADATA, config=CONFIG, client=repair_client)
    check("repair mode", repaired.generation_mode == "repaired")
    check("exactly one repair", repair_calls == 2)
    check("repair usage merged", repaired.usage.get("total", {}).get("total_tokens") == 10)
    check(
        "repair cached usage merged",
        repaired.usage.get("total", {}).get("input_tokens_details", {}).get("cached_tokens") == 5,
    )
    check(
        "repair reasoning usage merged",
        repaired.usage.get("total", {}).get("output_tokens_details", {}).get("reasoning_tokens") == 5,
    )

    # Two invalid submissions deterministically degrade.
    fallback_calls = 0

    def invalid_client(**kwargs):
        nonlocal fallback_calls
        fallback_calls += 1
        return _response({"security_invariant": "x", "behaviors": []})

    degraded = generate_patch_spec(METADATA, config=CONFIG, client=invalid_client)
    check("degraded mode", degraded.generation_mode == "degraded")
    check("fallback after two calls", fallback_calls == 2)
    check("degraded valid", not validate_patch_spec(degraded.spec, METADATA))

    # Cache layout, reuse accounting, stable digest, and no-write/no-network dry-run.
    with tempfile.TemporaryDirectory() as tmp:
        generation_calls = 0

        def cache_client(**kwargs):
            nonlocal generation_calls
            generation_calls += 1
            return _response(VALID_DRAFT)

        first = ensure_patch_spec(METADATA, config=CONFIG, cache_dir=tmp, client=cache_client)
        expected_path = patch_spec_cache_path(tmp, METADATA["cve_id"], first.cache_key)
        check("cache path layout", first.path == str(expected_path) and expected_path.is_file())
        second = ensure_patch_spec(
            METADATA,
            config=CONFIG,
            cache_dir=tmp,
            client=lambda **kwargs: (_ for _ in ()).throw(AssertionError("network on cache hit")),
        )
        check("cache hit", second.generation_mode == "cache_hit" and second.cache_hit)
        check("cache hit usage empty", second.usage == {})
        cache_summary = second.as_dict(include_spec=False)
        check(
            "cache summary separates generation and resolution",
            cache_summary.get("generation_mode") == "generated"
            and cache_summary.get("resolution_mode") == "cache_hit",
        )
        check("cache generated once", generation_calls == 1)
        check("stable digest", first.digest == second.digest == patch_spec_digest(first.spec))
        changed_model = ensure_patch_spec(
            METADATA,
            config=replace(CONFIG, model="gpt-5.5-prompt-revision"),
            cache_dir=tmp,
            dry_run=True,
            client=lambda **kwargs: (_ for _ in ()).throw(AssertionError("network in dry-run")),
        )
        check(
            "model change invalidates cache",
            not changed_model.cache_hit and changed_model.cache_key != first.cache_key,
        )

    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "patch_spec.json"
        dry = ensure_patch_spec(
            METADATA,
            config=CONFIG,
            output_path=output,
            dry_run=True,
            client=lambda **kwargs: (_ for _ in ()).throw(AssertionError("network in dry-run")),
        )
        check("dry run skeleton", dry.generation_mode == "dry_run_skeleton")
        check("dry run usage empty", dry.usage == {})
        check("dry run no write", not output.exists() and dry.path is None)

        metadata_path = Path(tmp) / "metadata.json"
        metadata_path.write_text(json.dumps({METADATA["cve_id"]: METADATA}), encoding="utf-8")
        cli_output = Path(tmp) / "cli.json"
        cli_stdout = io.StringIO()
        with contextlib.redirect_stdout(cli_stdout):
            cli_status = patchspec_main([
                "--metadata-json", str(metadata_path),
                "--cve-id", METADATA["cve_id"],
                "--output", str(cli_output),
                "--dry-run",
            ])
        check("CLI dry-run success", cli_status == 0)
        check("CLI dry-run no write", not cli_output.exists())

        missing_project = copy.deepcopy(METADATA)
        missing_project.pop("project", None)
        missing_project_path = Path(tmp) / "missing-project.json"
        missing_project_path.write_text(json.dumps(missing_project), encoding="utf-8")
        normalized_stdout = io.StringIO()
        with contextlib.redirect_stdout(normalized_stdout):
            normalized_status = patchspec_main([
                "--metadata-json", str(missing_project_path),
                "--cve-id", METADATA["cve_id"],
                "--output", str(cli_output),
                "--dry-run",
            ])
        normalized_cli = json.loads(normalized_stdout.getvalue())
        check(
            "CLI project normalization matches agent",
            normalized_status == 0
            and normalized_cli.get("spec", {}).get("source", {}).get("project") == "curl",
        )

    with tempfile.TemporaryDirectory() as tmp:
        invalid_path = patch_spec_cache_path(
            tmp, METADATA["cve_id"], skeleton["generation"]["cache_key"]
        )
        invalid_path.parent.mkdir(parents=True)
        invalid_path.write_text("{not-json", encoding="utf-8")
        try:
            ensure_patch_spec(METADATA, config=CONFIG, cache_dir=tmp, dry_run=True)
            check("invalid cache dry-run rejected", False)
        except PatchSpecValidationError as exc:
            check("invalid cache error labeled", "invalid_cache" in str(exc))
        rebuilt = ensure_patch_spec(
            METADATA,
            config=CONFIG,
            cache_dir=tmp,
            client=lambda **kwargs: _response(VALID_DRAFT),
        )
        check("invalid cache rebuilt", rebuilt.generation_mode == "generated")
        check("rebuilt cache valid", not validate_patch_spec(rebuilt.spec, METADATA))

    # Model view is explicitly allowlisted.
    view = model_input_view(METADATA)
    check("allowlisted model view", not ({"groundtruth", "binary_path", "patch_commit_message"} & set(view)))
    reduced_view = view.get("reduced_function_code", [{}])[0]
    check("reduced code key allowlist", set(reduced_view) == {"tailmatch"})
    check("unsafe vulnerability description omitted", "vulnerability_description" not in view)

    if failures:
        print("FAIL:", failures)
        return 1
    print("PATCHSPEC TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
