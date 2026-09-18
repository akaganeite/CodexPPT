"""Host-side Ghidra preparation, cache management, and Codex MCP config.

Ghidra never receives a path supplied by the model. The batch wrapper binds a
single anonymous target to a SHA256-keyed cache entry before ``codex exec`` is
started, and the stdio MCP server can only reopen that prepared entry.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .io import write_json


GHIDRA_CACHE_SCHEMA = 1
GHIDRA_MCP_SERVER = "straight_detect_ghidra"
GHIDRA_TOOL_NAMES = (
    "ghidra_locate_function",
    "ghidra_function_summary",
    "ghidra_cfg_slice",
    "ghidra_path_probe",
    "ghidra_call_args",
    "ghidra_decompile_slice",
)
DEFAULT_GHIDRA_CACHE_DIR = Path.home() / ".cache" / "straight_detect" / "ghidra"
LEGACY_GHIDRA_INSTALL_DIR = Path("/home/zhangxb/tools/ghidra_11.4.2_PUBLIC")
SOURCE_PROVENANCE = {
    "pptagent_commit": "4f5dc61c28f676c32e8e89c689ec7323f5d16cee",
    "pptagent_ghidra_manager_sha256": "20a687d6c5728ac3f10a82914a82ce611768a6c403a23583b9925d1daf81a1f2",
    "pptagent_ghidra_tools_sha256": "32a85b374d3bc1ff4d6e739d594da44b7f1310f7ea8c0e5f7c85887d9f0ef3f1",
}


@dataclass
class GhidraState:
    requested: str
    status: str = "disabled"
    enabled: bool = False
    cache_id: str = ""
    cache_path: str = ""
    analysis_dir: str = ""
    binary_path: str = ""
    install_dir: str = ""
    timeout_sec: int = 900
    reused_cache: bool = False
    error: str = ""
    versions: dict[str, str] = field(default_factory=dict)
    source_provenance: dict[str, str] = field(default_factory=lambda: dict(SOURCE_PROVENANCE))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_ghidra_install_dir(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit.expanduser().resolve()
    env_value = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if env_value:
        return Path(env_value).expanduser().resolve()
    if LEGACY_GHIDRA_INSTALL_DIR.is_dir():
        return LEGACY_GHIDRA_INSTALL_DIR.resolve()
    try:
        from pyghidra.launcher import HeadlessPyGhidraLauncher  # type: ignore

        launcher = HeadlessPyGhidraLauncher()
        discovered = Path(launcher._install_dir)  # pyghidra's resolved lastrun location
        if discovered.is_dir():
            return discovered.resolve()
    except Exception:
        pass
    return None


def ghidra_versions(install_dir: Path | None) -> dict[str, str]:
    versions: dict[str, str] = {}
    try:
        import pyghidra  # type: ignore

        versions["pyghidra"] = str(getattr(pyghidra, "__version__", "unknown"))
    except Exception as exc:
        versions["pyghidra_error"] = repr(exc)
    if install_dir is not None:
        versions["install_dir"] = str(install_dir)
        properties = install_dir / "Ghidra" / "application.properties"
        if properties.is_file():
            for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("application.version="):
                    versions["ghidra"] = line.split("=", 1)[1].strip()
                    break
    return versions


def ghidra_preflight(install_dir: Path | None) -> tuple[bool, str, dict[str, str]]:
    versions = ghidra_versions(install_dir)
    if "pyghidra_error" in versions:
        return False, versions["pyghidra_error"], versions
    if install_dir is None:
        return False, "could not locate a Ghidra installation", versions
    if install_dir is not None and not (install_dir / "Ghidra" / "application.properties").is_file():
        return False, f"invalid Ghidra install directory: {install_dir}", versions
    return True, "", versions


def prepare_ghidra(
    *,
    mode: str,
    binary: Path,
    cache_dir: Path,
    install_dir: Path | None,
    timeout_sec: int,
    state_path: Path,
    dry_run: bool = False,
) -> GhidraState:
    """Prepare one anonymous target and persist a per-testcase state artifact."""

    state = GhidraState(
        requested=mode,
        timeout_sec=timeout_sec,
    )
    if mode == "off":
        write_json(state_path, state.to_dict())
        return state

    resolved_install = resolve_ghidra_install_dir(install_dir)
    state.install_dir = str(resolved_install) if resolved_install is not None else ""

    ok, error, versions = ghidra_preflight(resolved_install)
    state.versions = versions
    if not ok:
        state.status = "failed"
        state.error = sanitize_error(error, binary, cache_dir, resolved_install)
        write_json(state_path, state.to_dict())
        return state

    if dry_run:
        state.status = "preflight_ready"
        write_json(state_path, state.to_dict())
        return state

    try:
        digest = sha256_file(binary)
        cache_dir = cache_dir.expanduser().resolve()
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_entry = cache_dir / digest
        lock_path = cache_dir / f"{digest}.lock"
        with lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            reused = cache_is_ready(cache_entry, digest, versions)
            if not reused:
                reset_cache_entry(cache_entry)
                cache_entry.mkdir(parents=True, exist_ok=True)
                target_copy = cache_entry / "target_binary"
                shutil.copy2(binary, target_copy)
                analysis_lock_path = cache_dir / ".analysis-jvm.lock"
                with analysis_lock_path.open("a+", encoding="utf-8") as analysis_lock:
                    fcntl.flock(analysis_lock.fileno(), fcntl.LOCK_EX)
                    summary = run_analysis_subprocess(
                        target_copy,
                        cache_entry,
                        resolved_install,
                        timeout_sec,
                    )
                meta = {
                    "ghidra_cache_schema": GHIDRA_CACHE_SCHEMA,
                    "binary_sha256": digest,
                    "binary_size": binary.stat().st_size,
                    "anonymous_binary_name": "target_binary",
                    "status": "ready",
                    "started_at": summary.pop("started_at"),
                    "finished_at": now_iso(),
                    "timeout_sec": timeout_sec,
                    "versions": versions,
                    "source_provenance": SOURCE_PROVENANCE,
                    **summary,
                }
                write_json(cache_entry / "analysis_meta.json", meta)
                (cache_entry / "analysis.log").write_text(
                    json.dumps(meta, ensure_ascii=False, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

        state.status = "ready"
        state.enabled = True
        state.cache_id = digest
        state.cache_path = str(cache_entry)
        state.analysis_dir = str(cache_entry / "project")
        state.binary_path = str(cache_entry / "target_binary")
        state.reused_cache = reused
    except Exception as exc:
        state.status = "failed"
        state.error = sanitize_error(repr(exc), binary, cache_dir, resolved_install)
    write_json(state_path, state.to_dict())
    return state


def ghidra_failure_is_fatal(mode: str, dry_run: bool, state: GhidraState) -> bool:
    return mode == "on" and not dry_run and not state.enabled


def cache_is_ready(cache_entry: Path, digest: str, versions: dict[str, str]) -> bool:
    meta_path = cache_entry / "analysis_meta.json"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(
        meta.get("ghidra_cache_schema") == GHIDRA_CACHE_SCHEMA
        and meta.get("binary_sha256") == digest
        and meta.get("status") == "ready"
        and meta.get("versions") == versions
        and (cache_entry / "target_binary").is_file()
        and (cache_entry / "project").is_dir()
    )


def reset_cache_entry(cache_entry: Path) -> None:
    """Remove only one validated SHA256 cache entry before rebuilding it."""

    if not cache_entry.exists():
        return
    if len(cache_entry.name) != 64 or any(ch not in "0123456789abcdef" for ch in cache_entry.name):
        raise ValueError(f"refusing to reset non-SHA256 cache entry: {cache_entry}")
    shutil.rmtree(cache_entry)


def run_analysis_subprocess(
    binary: Path,
    cache_entry: Path,
    install_dir: Path | None,
    timeout_sec: int,
) -> dict[str, Any]:
    summary_path = cache_entry / "analysis_summary.json"
    cmd = [
        sys.executable,
        "-m",
        "codex_batch.ghidra_analyze",
        "--binary",
        str(binary),
        "--cache-entry",
        str(cache_entry),
        "--summary",
        str(summary_path),
    ]
    if install_dir is not None:
        cmd.extend(["--install-dir", str(install_dir)])
    started_at = now_iso()
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Ghidra analysis exceeded {timeout_sec}s") from exc
    (cache_entry / "analysis.stdout").write_text(completed.stdout, encoding="utf-8", errors="replace")
    (cache_entry / "analysis.stderr").write_text(completed.stderr, encoding="utf-8", errors="replace")
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"pyghidra analysis failed: {detail[-2000:]}")
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Ghidra analyzer did not produce a valid summary") from exc
    if not isinstance(summary, dict):
        raise RuntimeError("Ghidra analyzer summary is not an object")
    summary["started_at"] = started_at
    return summary


def sanitize_error(text: str, binary: Path, cache_dir: Path, install_dir: Path | None) -> str:
    value = str(text)
    for path in (binary, cache_dir, install_dir):
        if path is not None:
            value = value.replace(str(path), "target_binary")
    return value[:4000]


def list_codex_mcp_server_names(codex_bin: str, timeout_sec: int = 30) -> list[str]:
    """Return configured MCP ids so a detection run can explicitly disable them."""

    try:
        completed = subprocess.run(
            [codex_bin, "mcp", "list", "--json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"cannot enumerate Codex MCP servers: {exc!r}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"cannot enumerate Codex MCP servers: {detail[-1000:]}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("codex mcp list --json returned invalid JSON") from exc
    if not isinstance(payload, list):
        raise RuntimeError("codex mcp list --json did not return a list")
    names = []
    for item in payload:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]:
            names.append(item["name"])
    return sorted(set(names))


def mcp_server_overrides(
    state: GhidraState,
    *,
    script_dir: Path,
    query_log: Path,
    required: bool,
    disabled_server_names: list[str],
) -> list[str]:
    """Build CLI ``-c`` overrides that isolate and register the Ghidra MCP."""

    overrides: list[str] = []
    for name in disabled_server_names:
        if name != GHIDRA_MCP_SERVER:
            overrides.extend(["-c", f"mcp_servers.{name}.enabled=false"])
    if not state.enabled:
        return overrides
    args = [
        "-m",
        "codex_batch.ghidra_mcp",
        "--cache-entry",
        state.cache_path,
        "--query-log",
        str(query_log),
        "--timeout",
        str(state.timeout_sec),
    ]
    if state.install_dir:
        args.extend(["--install-dir", state.install_dir])
    config = {
        "command": sys.executable,
        "args": args,
        "cwd": str(script_dir),
        "enabled": True,
        "required": required,
        "startup_timeout_sec": min(max(state.timeout_sec, 10), 3600),
        "tool_timeout_sec": min(max(state.timeout_sec, 60), 3600),
        "enabled_tools": list(GHIDRA_TOOL_NAMES),
        "default_tools_approval_mode": "approve",
    }
    env_vars = [name for name in ("PYTHONPATH", "JAVA_HOME") if os.environ.get(name)]
    if env_vars:
        config["env_vars"] = env_vars
    overrides.extend(["-c", f"mcp_servers.{GHIDRA_MCP_SERVER}={toml_inline(config)}"])
    return overrides


def toml_inline(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_inline(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{key}={toml_inline(item)}" for key, item in value.items()) + "}"
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")
