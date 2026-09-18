from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import resolve_requested_binary


@dataclass
class AnonymousTargetSet:
    tempdir: tempfile.TemporaryDirectory[str]
    target_dir: Path
    cd: Path
    requested_binaries: list[str]
    binary_resolution: dict[str, str]
    anonymous_to_original: dict[str, str]
    original_to_anonymous: dict[str, str]
    actual_mapping: dict[str, str]
    debug_mapping: dict[str, str]
    safe_objdump_helper: str
    safe_objdump_dir: Path | None

    def cleanup(self) -> None:
        restore_permissions(self.cd)
        self.tempdir.cleanup()


def prepare_anonymous_targets(
    cve: str,
    requested_binaries: list[str],
    source_target_dir: Path,
    compiler: str,
    opt: str,
    safe_objdump_source_dir: Path,
    debug_dir: Path | None = None,
    anonymize: bool = True,
) -> AnonymousTargetSet:
    tempdir = tempfile.TemporaryDirectory(prefix=f"codex-targets-{safe_name(cve)}-")
    temp_root = Path(tempdir.name).resolve()
    target_dir = temp_root / "targets"
    target_dir.mkdir()

    requested_anon: list[str] = []
    binary_resolution: dict[str, str] = {}
    anonymous_to_original: dict[str, str] = {}
    original_to_anonymous: dict[str, str] = {}
    actual_mapping: dict[str, str] = {}
    debug_mapping: dict[str, str] = {}

    for index, requested in enumerate(requested_binaries, 1):
        original_actual = resolve_requested_binary(source_target_dir, requested, compiler, opt)
        anonymous_requested = f"target_{index:03d}" if anonymize else requested
        anonymous_actual = anonymous_requested if anonymize else original_actual
        src = source_target_dir / original_actual
        dst = target_dir / anonymous_actual
        if src.is_file():
            if debug_dir is None:
                shutil.copy2(src, dst)
            else:
                debug_src = resolve_debug_companion(debug_dir, original_actual)
                merge_debug_companion(src, debug_src, dst)
                debug_mapping[requested] = str(debug_src)

        requested_anon.append(anonymous_requested)
        binary_resolution[anonymous_requested] = anonymous_actual
        anonymous_to_original[anonymous_requested] = requested
        original_to_anonymous[requested] = anonymous_requested
        actual_mapping[requested] = original_actual

    helper_src = safe_objdump_source_dir / "safe_objdump.py"
    config_src = safe_objdump_source_dir / "config.json"
    helper_dst = temp_root / "safe_objdump.py"
    config_dst = temp_root / "config.json"
    shutil.copy2(helper_src, helper_dst)
    if config_src.is_file():
        shutil.copy2(config_src, config_dst)

    make_static_read_only(temp_root)

    return AnonymousTargetSet(
        tempdir=tempdir,
        target_dir=target_dir,
        cd=temp_root,
        requested_binaries=requested_anon,
        binary_resolution=binary_resolution,
        anonymous_to_original=anonymous_to_original,
        original_to_anonymous=original_to_anonymous,
        actual_mapping=actual_mapping,
        debug_mapping=debug_mapping,
        safe_objdump_helper="./safe_objdump.py",
        safe_objdump_dir=None,
    )


def make_static_read_only(root: Path) -> None:
    """Make the Codex-visible temporary tree readable but non-writable/non-executable."""
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o555)
        else:
            path.chmod(0o444)
    root.chmod(0o555)


def restore_permissions(root: Path) -> None:
    """Restore temporary-tree permissions so TemporaryDirectory can remove it."""
    if not root.exists():
        return
    descendants = sorted(root.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for path in descendants:
        try:
            path.chmod(0o755 if path.is_dir() else 0o644)
        except FileNotFoundError:
            pass
    try:
        root.chmod(0o700)
    except FileNotFoundError:
        pass


def resolve_debug_companion(debug_dir: Path, binary_name: str) -> Path:
    """Return the external debug companion for one dataset target binary."""
    candidates = [debug_dir / f"{binary_name}.debug", debug_dir / binary_name]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    tried = ", ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(f"debug companion not found for {binary_name}; tried: {tried}")


def merge_debug_companion(binary: Path, debug_file: Path, output: Path) -> None:
    """Create one ELF containing executable sections, symbols, and DWARF data."""
    try:
        completed = subprocess.run(
            ["eu-unstrip", "-o", str(output), str(binary), str(debug_file)],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("eu-unstrip is required for --debug-dir but is not installed") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"eu-unstrip failed for {binary.name}: {detail}")


def remap_result_to_original(
    result: dict[str, Any],
    anonymous_to_original: dict[str, str],
    requested_binaries: list[str],
    anonymous_target_dir: Path | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for anonymous, original in anonymous_to_original.items():
        if anonymous in result:
            out[original] = remap_row_text(result[anonymous], anonymous_to_original, anonymous_target_dir)
    for original in requested_binaries:
        if original not in out:
            out[original] = {
                "status": "error",
                "confidence": "low",
                "evidence": ["codex output did not contain this requested binary after de-anonymization"],
                "reasoning": "Missing per-binary result in anonymous final JSON.",
            }
    return out


def remap_row_text(
    row: Any,
    anonymous_to_original: dict[str, str],
    anonymous_target_dir: Path | None,
) -> Any:
    if not isinstance(row, dict):
        return row

    rewritten = dict(row)
    if isinstance(rewritten.get("evidence"), list):
        rewritten["evidence"] = [
            remap_text(str(item), anonymous_to_original, anonymous_target_dir)
            for item in rewritten["evidence"]
        ]
    elif "evidence" in rewritten:
        rewritten["evidence"] = remap_text(str(rewritten["evidence"]), anonymous_to_original, anonymous_target_dir)

    if "reasoning" in rewritten:
        rewritten["reasoning"] = remap_text(str(rewritten["reasoning"]), anonymous_to_original, anonymous_target_dir)
    return rewritten


def remap_text(
    text: str,
    anonymous_to_original: dict[str, str],
    anonymous_target_dir: Path | None,
) -> str:
    for anonymous, original in sorted(anonymous_to_original.items(), reverse=True):
        if anonymous_target_dir is not None:
            text = text.replace(str(anonymous_target_dir / anonymous), original)
        text = text.replace(anonymous, original)
    return text


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)
