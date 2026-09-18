"""Anonymous per-run target-binary workspace.

The original filename/path often encodes a package version (e.g.
``curl-7.29.0-libcurl-gcc-O0``). The model-facing harness never needs that
identity - and leaving it visible invites version-number "hacks" (look up the
version against the CVE's affected range instead of inspecting binary
semantics). Every run therefore copies the target into a fresh temp dir under
a neutral name and inspects the copy, so the real name never reaches the prompt,
the transcript, the evidence ledger, or the final artifact.

Mirrors ``../pptagent/core/binary_workspace.py`` so the two harnesses behave
identically. Cleanup is the caller's responsibility: wrap the run in
``try/finally`` and call ``workspace.cleanup()`` (which removes the whole temp
tree). ``tempfile.TemporaryDirectory`` also self-cleans on GC, so the
``claudeagent-target-`` prefix makes any stragglers identifiable.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from claudeagent.common import expand


@dataclass
class AnonymousBinaryWorkspace:
    """Temporary copy of one target binary under a version-free name."""

    tempdir: tempfile.TemporaryDirectory[str]
    original_path: Path
    anonymous_name: str
    target_dir: Path
    binary_path: Path
    copied: bool
    debug_companion_path: Path | None
    debug_merged: bool
    original_to_anonymous: dict[str, str]
    anonymous_to_original: dict[str, str]

    def cleanup(self) -> None:
        self.tempdir.cleanup()


def resolve_debug_companion(binary: str | Path, debug_dir: str) -> Path | None:
    """Resolve ``<debug_dir>/<binary-basename>.debug`` when debug mode is enabled."""
    if not debug_dir:
        return None
    companion = expand(debug_dir) / f"{Path(binary).name}.debug"
    if not companion.is_file():
        raise FileNotFoundError(f"debug companion missing: {companion}")
    return companion


def _merge_debug_companion(stripped: Path, debug_companion: Path, output: Path) -> None:
    """Build one unstripped ELF without mounting the companion in the sandbox."""
    eu_unstrip = shutil.which("eu-unstrip")
    if not eu_unstrip:
        raise RuntimeError("eu-unstrip is required when --debug-dir is supplied")
    proc = subprocess.run(
        [eu_unstrip, "-o", str(output), str(stripped), str(debug_companion)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0 or not output.is_file():
        detail = (proc.stderr or proc.stdout or "unknown eu-unstrip failure").strip()
        raise RuntimeError(f"eu-unstrip failed: {detail[:1000]}")


def prepare_anonymous_binary(
    binary: str,
    anonymous_name: str = "target_binary",
    debug_companion: str | Path | None = None,
) -> AnonymousBinaryWorkspace:
    """Copy the target binary into a temporary directory under an anonymous name.

    The original filename/path may encode package versions. The model-facing
    harness never needs that identity, so every run inspects the copied
    artifact instead. If ``binary`` is not a regular file, ``copied`` stays
    ``False`` but the workspace is still returned - preflight then reports the
    missing file against the anonymous path, exactly as before.
    """
    source = expand(binary)
    companion = Path(debug_companion).expanduser().resolve() if debug_companion else None
    tempdir = tempfile.TemporaryDirectory(prefix="claudeagent-target-")
    temp_root = Path(tempdir.name).resolve()
    target_dir = temp_root / "targets"
    target_dir.mkdir()
    anonymous_path = target_dir / anonymous_name
    copied = False
    debug_merged = False
    if source.is_file():
        if companion is None:
            shutil.copy2(source, anonymous_path)
        else:
            stripped_copy = target_dir / f"{anonymous_name}.stripped"
            shutil.copy2(source, stripped_copy)
            _merge_debug_companion(stripped_copy, companion, anonymous_path)
            debug_merged = True
        copied = True
    return AnonymousBinaryWorkspace(
        tempdir=tempdir,
        original_path=source,
        anonymous_name=anonymous_name,
        target_dir=target_dir,
        binary_path=anonymous_path,
        copied=copied,
        debug_companion_path=companion,
        debug_merged=debug_merged,
        original_to_anonymous={str(source): anonymous_name},
        anonymous_to_original={anonymous_name: str(source)},
    )
