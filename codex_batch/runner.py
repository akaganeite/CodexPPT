from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from .io import is_relative_to


def run_codex(
    prompt: str,
    cve: str,
    args: argparse.Namespace,
    raw_dir: Path,
    schema_path: Path,
) -> tuple[int, str, str, Path]:
    last_message = raw_dir / f"{cve}.last.json"
    stdout_path = raw_dir / f"{cve}.stdout"
    stderr_path = raw_dir / f"{cve}.stderr"
    prompt_path = raw_dir / f"{cve}.prompt.txt"
    prompt_path.write_text(prompt, encoding="utf-8")

    cmd = [
        args.codex_bin,
        "exec",
        "--skip-git-repo-check",
        "--sandbox",
        args.sandbox,
        "--cd",
        str(args.cd),
        "--output-schema",
        str(schema_path),
        "--output-last-message",
        str(last_message),
    ]
    if not is_relative_to(args.target_dir, args.cd):
        cmd.extend(["--add-dir", str(args.target_dir)])
    if hasattr(args, "safe_objdump_dir") and not is_relative_to(args.safe_objdump_dir, args.cd):
        cmd.extend(["--add-dir", str(args.safe_objdump_dir)])
    if args.model:
        cmd.extend(["--model", args.model])
    if args.profile:
        cmd.extend(["--profile", args.profile])
    if args.codex_json_events:
        cmd.append("--json")
    cmd.append("-")

    proc = subprocess.run(
        cmd,
        input=prompt,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=args.timeout,
        check=False,
    )
    stdout_path.write_text(proc.stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(proc.stderr, encoding="utf-8", errors="replace")

    final_text = ""
    if last_message.exists():
        final_text = last_message.read_text(encoding="utf-8", errors="replace")
    if not final_text.strip():
        final_text = proc.stdout
    return proc.returncode, final_text, proc.stderr, last_message
