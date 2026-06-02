from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import requested_binary_to_actual


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
    safe_objdump_helper: str
    safe_objdump_dir: Path | None

    def cleanup(self) -> None:
        self.tempdir.cleanup()


def prepare_anonymous_targets(
    cve: str,
    requested_binaries: list[str],
    source_target_dir: Path,
    opt: str,
    safe_objdump_source_dir: Path,
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

    for index, requested in enumerate(requested_binaries, 1):
        anonymous_requested = f"target_{index:03d}"
        anonymous_actual = anonymous_requested
        original_actual = requested_binary_to_actual(requested, opt)
        src = source_target_dir / original_actual
        dst = target_dir / anonymous_actual
        if src.is_file():
            shutil.copy2(src, dst)

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

    return AnonymousTargetSet(
        tempdir=tempdir,
        target_dir=target_dir,
        cd=temp_root,
        requested_binaries=requested_anon,
        binary_resolution=binary_resolution,
        anonymous_to_original=anonymous_to_original,
        original_to_anonymous=original_to_anonymous,
        actual_mapping=actual_mapping,
        safe_objdump_helper="./safe_objdump.py",
        safe_objdump_dir=None,
    )


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
