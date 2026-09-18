from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

from utils.io import read_json, write_json
from utils.paths import ROOT, SCHEMA_PATH


def build_codex_exec_command(
    *,
    prompt_path: Path,
    output_path: Path,
    schema_path: Path = SCHEMA_PATH,
    codex_model: str,
    codex_sandbox: str,
    add_dirs: list[Path],
) -> list[str]:
    command = [
        "codex",
        "--ask-for-approval",
        "never",
        "--sandbox",
        codex_sandbox,
        "exec",
        "--skip-git-repo-check",
        "-C",
        str(ROOT),
        "--output-schema",
        str(schema_path),
        "-o",
        str(output_path),
        "--json",
    ]
    if codex_model:
        command.extend(["--model", codex_model])
    for add_dir in add_dirs:
        command.extend(["--add-dir", str(add_dir)])
    command.append(prompt_path.read_text(encoding="utf-8"))
    return command


def run_codex_exec_json(
    *,
    prompt_path: Path,
    output_path: Path,
    json_events_path: Path,
    schema_path: Path = SCHEMA_PATH,
    codex_model: str,
    codex_sandbox: str,
    add_dirs: list[Path],
    timeout: int | None = None,
) -> dict[str, Any]:
    command = build_codex_exec_command(
        prompt_path=prompt_path,
        output_path=output_path,
        schema_path=schema_path,
        codex_model=codex_model,
        codex_sandbox=codex_sandbox,
        add_dirs=add_dirs,
    )

    started = time.time()
    json_events_path.parent.mkdir(parents=True, exist_ok=True)
    with json_events_path.open("w", encoding="utf-8", errors="replace") as out:
        proc = subprocess.run(
            [str(part) for part in command],
            cwd=str(ROOT),
            stdout=out,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
            timeout=timeout,
        )
    seconds = time.time() - started

    result = read_json(output_path, {}) if output_path.exists() else {}
    result.setdefault("status", "codex_failed" if proc.returncode else "unknown")
    result.setdefault("retry_passed", False)
    result["codex_returncode"] = proc.returncode
    result["codex_seconds"] = seconds
    result["codex_events_path"] = str(json_events_path)
    write_json(output_path, result)
    return result
