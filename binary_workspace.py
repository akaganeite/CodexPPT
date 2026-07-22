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
    original_to_anonymous: dict[str, str]
    anonymous_to_original: dict[str, str]

    def cleanup(self) -> None:
        self.tempdir.cleanup()


def prepare_anonymous_binary(binary: str, anonymous_name: str = "target_binary") -> AnonymousBinaryWorkspace:
    """Copy the target binary into a temporary directory under an anonymous name.

    The original filename/path may encode package versions. The model-facing
    harness never needs that identity, so every run inspects the copied
    artifact instead. If ``binary`` is not a regular file, ``copied`` stays
    ``False`` but the workspace is still returned - preflight then reports the
    missing file against the anonymous path, exactly as before.
    """
    source = expand(binary)
    tempdir = tempfile.TemporaryDirectory(prefix="claudeagent-target-")
    temp_root = Path(tempdir.name).resolve()
    target_dir = temp_root / "targets"
    target_dir.mkdir()
    anonymous_path = target_dir / anonymous_name
    copied = False
    if source.is_file():
        shutil.copy2(source, anonymous_path)
        copied = True
    return AnonymousBinaryWorkspace(
        tempdir=tempdir,
        original_path=source,
        anonymous_name=anonymous_name,
        target_dir=target_dir,
        binary_path=anonymous_path,
        copied=copied,
        original_to_anonymous={str(source): anonymous_name},
        anonymous_to_original={anonymous_name: str(source)},
    )
