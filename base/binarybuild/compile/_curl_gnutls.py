"""Isolated source preparation and dependency probing for curl's GnuTLS build."""

from __future__ import annotations

import tempfile
from pathlib import Path

from builder.config import BuildConfig
from utils.command import run_command


def probe_gnutls(config: BuildConfig, worktree: Path, log_path: Path, env: dict[str, str]) -> bool:
    # The central cross contract does not supply target TLS development packages.
    if config.architecture != "x86_64":
        return False
    with tempfile.TemporaryDirectory(prefix=".agentic-gnutls-probe-", dir=worktree) as tmp:
        root = Path(tmp)
        source = root / "probe.c"
        source.write_text(
            '#include <gnutls/gnutls.h>\n'
            'int main(void) { return gnutls_check_version(0) == 0; }\n',
            encoding="utf-8",
        )
        return run_command(
            [config.toolchain.c_compiler, *config.toolchain.compiler_flags,
             str(source), "-lgnutls", "-o", str(root / "probe")],
            cwd=worktree, log_path=log_path, env=env,
        ).ok


def prepare_gnutls_source(worktree: Path, commit: str, log_dir: Path, profile: str) -> tuple[Path | None, list[str]]:
    """Archive the exact commit, never the configured/modified source checkout."""
    destination = worktree / ".agentic-gnutls"
    marker = destination / ".agentic-source-commit"
    if destination.exists():
        try:
            return (destination if marker.read_text(encoding="utf-8").strip() == commit else None), []
        except OSError:
            return None, []
    logs: list[str] = []
    with tempfile.TemporaryDirectory(prefix=".agentic-tls-source-", dir=worktree) as tmp:
        root = Path(tmp)
        archive = root / "source.tar"
        source = root / "source"
        source.mkdir()
        commands = (
            ["git", "archive", "--format=tar", f"--output={archive}", commit],
            ["tar", "-xf", str(archive), "--no-same-owner", "-C", str(source)],
        )
        for index, command in enumerate(commands, 1):
            log_path = log_dir / f"{commit[:12]}-{profile}-source-{index}.log"
            logs.append(str(log_path))
            if not run_command(command, cwd=worktree, log_path=log_path).ok:
                return None, logs
        (source / marker.name).write_text(commit + "\n", encoding="utf-8")
        source.rename(destination)
    return destination, logs
