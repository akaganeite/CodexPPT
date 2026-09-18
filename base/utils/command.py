from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from utils.io import utc_now


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    seconds: float
    log_path: Path

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def shell_join(command: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


def run_command(command: list[str], *, cwd: Path, log_path: Path, env: dict[str, str] | None = None) -> CommandResult:
    started = time.time()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        log.write(f"$ {shell_join(command)}\n")
        log.write(f"cwd: {cwd}\n")
        log.write(f"started_at: {utc_now()}\n\n")
        log.flush()
        proc = subprocess.run(
            [str(part) for part in command],
            cwd=str(cwd),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
        )
        seconds = time.time() - started
        log.write(f"\nfinished_at: {utc_now()}\n")
        log.write(f"seconds: {seconds:.2f}\n")
        log.write(f"returncode: {proc.returncode}\n")
    return CommandResult(command=command, returncode=proc.returncode, seconds=seconds, log_path=log_path)
