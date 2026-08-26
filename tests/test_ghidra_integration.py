from __future__ import annotations

import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_batch import ghidra_manager, ghidra_tools, orchestrator
from codex_batch.ghidra_manager import (
    GHIDRA_TOOL_NAMES,
    GhidraState,
    ghidra_failure_is_fatal,
    mcp_server_overrides,
    prepare_ghidra,
    sha256_file,
)
from codex_batch.prompt import GHIDRA_GUIDANCE, build_prompt


def test_sha256_cache_key(tmp_path: Path) -> None:
    binary = tmp_path / "target_binary"
    binary.write_bytes(b"binary bytes")
    assert sha256_file(binary) == "4f463802bc436efdd9a0c4e8c999ec3d37450657bd50b579d796b58bc9d3f1ef"


def test_modes_and_strict_failure(tmp_path: Path) -> None:
    binary = tmp_path / "target_binary"
    binary.write_bytes(b"ELF")
    state = prepare_ghidra(
        mode="off",
        binary=binary,
        cache_dir=tmp_path / "cache",
        install_dir=None,
        timeout_sec=10,
        state_path=tmp_path / "case.ghidra.json",
    )
    assert state.status == "disabled"
    failed = GhidraState(requested="on", status="failed", error="no Ghidra")
    assert ghidra_failure_is_fatal("on", False, failed)
    assert not ghidra_failure_is_fatal("auto", False, failed)
    assert not ghidra_failure_is_fatal("on", True, failed)


def test_cache_lock_allows_one_analysis(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "target_binary"
    binary.write_bytes(b"same binary")
    count = 0
    count_lock = threading.Lock()

    monkeypatch.setattr(ghidra_manager, "ghidra_preflight", lambda _install: (True, "", {"pyghidra": "test"}))

    def fake_analyze(_binary: Path, cache_entry: Path, _install: Path | None, _timeout: int):
        nonlocal count
        with count_lock:
            count += 1
        time.sleep(0.05)
        (cache_entry / "project").mkdir()
        return {"function_count": 1, "string_count": 0, "callgraph_edges": 0, "started_at": "now"}

    monkeypatch.setattr(ghidra_manager, "run_analysis_subprocess", fake_analyze)

    def prepare(index: int):
        return prepare_ghidra(
            mode="on",
            binary=binary,
            cache_dir=tmp_path / "cache",
            install_dir=None,
            timeout_sec=10,
            state_path=tmp_path / f"case-{index}.json",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        states = list(executor.map(prepare, [1, 2]))
    assert count == 1
    assert all(state.enabled for state in states)
    assert sorted(state.reused_cache for state in states) == [False, True]


def test_analysis_jvm_capacity_lock_serializes_different_hashes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binaries = []
    for index in (1, 2):
        binary = tmp_path / f"target_binary_{index}"
        binary.write_bytes(f"binary {index}".encode())
        binaries.append(binary)
    active = 0
    peak = 0
    guard = threading.Lock()
    monkeypatch.setattr(ghidra_manager, "ghidra_preflight", lambda _install: (True, "", {"pyghidra": "test"}))

    def fake_analyze(_binary: Path, cache_entry: Path, _install: Path | None, _timeout: int):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        (cache_entry / "project").mkdir()
        with guard:
            active -= 1
        return {"function_count": 1, "string_count": 0, "callgraph_edges": 0, "started_at": "now"}

    monkeypatch.setattr(ghidra_manager, "run_analysis_subprocess", fake_analyze)

    def prepare(index: int):
        return prepare_ghidra(
            mode="on", binary=binaries[index], cache_dir=tmp_path / "cache", install_dir=None,
            timeout_sec=10, state_path=tmp_path / f"case-{index}.json",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        states = list(executor.map(prepare, [0, 1]))
    assert peak == 1
    assert all(state.status == "ready" for state in states)


def test_failed_cache_retries(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "target_binary"
    binary.write_bytes(b"retry binary")
    attempts = 0
    monkeypatch.setattr(ghidra_manager, "ghidra_preflight", lambda _install: (True, "", {"pyghidra": "test"}))

    def flaky(_binary: Path, cache_entry: Path, _install: Path | None, _timeout: int):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("first failure")
        (cache_entry / "project").mkdir()
        return {"function_count": 1, "string_count": 0, "callgraph_edges": 0, "started_at": "now"}

    monkeypatch.setattr(ghidra_manager, "run_analysis_subprocess", flaky)
    first = prepare_ghidra(
        mode="auto",
        binary=binary,
        cache_dir=tmp_path / "cache",
        install_dir=None,
        timeout_sec=10,
        state_path=tmp_path / "first.json",
    )
    second = prepare_ghidra(
        mode="auto",
        binary=binary,
        cache_dir=tmp_path / "cache",
        install_dir=None,
        timeout_sec=10,
        state_path=tmp_path / "second.json",
    )
    assert first.status == "failed"
    assert second.status == "ready"
    assert attempts == 2


def test_cache_schema_mismatch_rebuilds(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "target_binary"
    binary.write_bytes(b"schema binary")
    attempts = 0
    monkeypatch.setattr(ghidra_manager, "ghidra_preflight", lambda _install: (True, "", {"pyghidra": "test"}))

    def fake_analyze(_binary: Path, cache_entry: Path, _install: Path | None, _timeout: int):
        nonlocal attempts
        attempts += 1
        (cache_entry / "project").mkdir()
        return {"function_count": 1, "string_count": 0, "callgraph_edges": 0, "started_at": "now"}

    monkeypatch.setattr(ghidra_manager, "run_analysis_subprocess", fake_analyze)
    first = prepare_ghidra(
        mode="on", binary=binary, cache_dir=tmp_path / "cache", install_dir=None,
        timeout_sec=10, state_path=tmp_path / "first.json",
    )
    meta_path = Path(first.cache_path) / "analysis_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["ghidra_cache_schema"] = -1
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    second = prepare_ghidra(
        mode="on", binary=binary, cache_dir=tmp_path / "cache", install_dir=None,
        timeout_sec=10, state_path=tmp_path / "second.json",
    )
    assert second.status == "ready"
    assert not second.reused_cache
    assert attempts == 2


def test_on_failure_writes_testcase_error_without_codex(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target_dir = tmp_path / "targets"
    raw_dir = tmp_path / "raw"
    target_dir.mkdir()
    raw_dir.mkdir()
    (target_dir / "sample").write_bytes(b"ELF")
    output = tmp_path / "results.json"
    args = SimpleNamespace(
        no_anonymize_targets=False,
        debug_dir=None,
        compiler="gcc",
        opt="O2",
        safe_objdump_dir=Path(orchestrator.__file__).resolve().parent.parent / "utils",
        original_cd=target_dir,
        ghidra="on",
        ghidra_cache_dir=tmp_path / "cache",
        ghidra_install_dir=None,
        ghidra_timeout=10,
        dry_run=False,
        metadata="full",
    )
    monkeypatch.setattr(
        orchestrator,
        "prepare_ghidra",
        lambda **_kwargs: GhidraState(requested="on", status="failed", error="preflight failed"),
    )
    monkeypatch.setattr(
        orchestrator,
        "run_codex",
        lambda *_args, **_kwargs: pytest.fail("Codex must not start after required Ghidra failure"),
    )
    merged: dict[str, object] = {}
    orchestrator.process_cve(
        "CVE-X",
        1,
        iter([1]),
        {"CVE-X": {}},
        {"CVE-X": ["sample"]},
        merged,
        threading.Lock(),
        {"output": output, "raw_dir": raw_dir, "target_dir": target_dir},
        args,
        Path(orchestrator.__file__).resolve().parent.parent,
        requested_binaries=["sample"],
        run_id="CVE-X__sample",
    )
    assert merged["CVE-X"]["sample"]["status"] == "error"
    assert "preflight failed" in merged["CVE-X"]["sample"]["evidence"][0]


def test_mcp_overrides_disable_other_servers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PYTHONPATH", "/tmp/testdeps")
    state = GhidraState(
        requested="on",
        status="ready",
        enabled=True,
        cache_path=str(tmp_path / ("a" * 64)),
        install_dir="/opt/ghidra",
        timeout_sec=123,
    )
    overrides = mcp_server_overrides(
        state,
        script_dir=tmp_path,
        query_log=tmp_path / "queries.jsonl",
        required=True,
        disabled_server_names=["node_repl", "openaiDeveloperDocs"],
    )
    text = " ".join(overrides)
    assert "mcp_servers.node_repl.enabled=false" in text
    assert "mcp_servers.openaiDeveloperDocs.enabled=false" in text
    assert "required=true" in text
    assert 'default_tools_approval_mode="approve"' in text
    assert 'env_vars=["PYTHONPATH"]' in text
    assert all(name in text for name in GHIDRA_TOOL_NAMES)


def test_bounded_sanitized_raw_first_response(tmp_path: Path) -> None:
    cache_entry = tmp_path / ("b" * 64)
    cache_entry.mkdir()
    (cache_entry / "target_binary").write_bytes(b"ELF")
    (cache_entry / "project").mkdir()
    ghidra_tools.configure_runtime(cache_entry, None, tmp_path / "queries.jsonl", 10)
    result = ghidra_tools._response(
        "ghidra_decompile_slice",
        {"function": str(cache_entry / "secret")},
        str(cache_entry) + " /opt/private/ghidra/file " + ("X" * 30000),
        {"available": True, "private_path": str(cache_entry / "facts")},
        [{"kind": "ghidra_decompile_slice", "claim": "advisory", "excerpts": ["pseudo"]}],
    )
    assert str(cache_entry) not in json.dumps(result)
    assert "/opt/private/ghidra/file" not in json.dumps(result)
    assert result["truncated"] is True
    assert len(result["stdout_head"] + result["stdout_tail"]) <= ghidra_tools.GHIDRA_STDOUT_BUDGET
    assert result["evidence"][0]["raw_backed"] is False

    huge = ghidra_tools._response(
        "ghidra_cfg_slice",
        {},
        "raw",
        {"available": True, "rows": [{"text": "Y" * 5000} for _ in range(100)]},
    )
    assert huge["truncated"] is True
    assert huge["parsed_facts"]["status"] == "parsed_facts_truncated"
    assert len(json.dumps(huge)) < 60000


def test_generic_constant_is_not_a_strong_locator_anchor() -> None:
    assert ghidra_tools._is_generic_constant("0xc")
    assert ghidra_tools._is_generic_constant("255")
    assert not ghidra_tools._is_generic_constant("0x2801")
    assert not ghidra_tools._is_generic_constant("SSL3_MT_SERVER_KEY_EXCHANGE")


def test_giant_text_boundary_is_rejected() -> None:
    class Block:
        def getSize(self):
            return 100_000

    class Memory:
        def getBlock(self, name: str):
            assert name == ".text"
            return Block()

    class Body:
        def getNumAddresses(self):
            return 80_000

    class Function:
        def getBody(self):
            return Body()

    class Program:
        def getMemory(self):
            return Memory()

    giant, facts = ghidra_tools._function_covers_giant_text(Program(), Function())
    assert giant
    assert facts["text_coverage_ratio"] == 0.8


def test_prompt_mentions_ghidra_only_when_enabled(tmp_path: Path) -> None:
    template = tmp_path / "prompt.md"
    template.write_text("payload={{TASK_PAYLOAD_JSON}} helper={{SAFE_OBJDUMP_HELPER}}", encoding="utf-8")
    disabled = build_prompt(template, "CVE-X", {}, ["target_001"], tmp_path, "gcc", "O2", "./safe.py")
    enabled = build_prompt(
        template,
        "CVE-X",
        {},
        ["target_001"],
        tmp_path,
        "gcc",
        "O2",
        "./safe.py",
        ghidra_enabled=True,
    )
    assert GHIDRA_GUIDANCE.strip() not in disabled
    assert GHIDRA_GUIDANCE.strip() in enabled


def test_mcp_exposes_exact_six_bounded_schemas() -> None:
    pytest.importorskip("mcp")
    from codex_batch.ghidra_mcp import build_server

    schemas = {tool.name: tool.input_schema for tool in asyncio.run(build_server().list_tools())}
    assert set(schemas) == set(GHIDRA_TOOL_NAMES)
    assert schemas["ghidra_cfg_slice"]["properties"]["radius_blocks"]["maximum"] == 8
    assert schemas["ghidra_path_probe"]["properties"]["require_patterns"]["maxItems"] == 12
    assert schemas["ghidra_decompile_slice"]["properties"]["max_lines"]["maximum"] == 80
    assert all("path" not in schema["properties"] for schema in schemas.values())
