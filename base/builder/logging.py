from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


LEVELS = ("trace", "warn", "error")
RESERVED_FIELDS = {"time", "level", "stage", "message"}
MAX_CONSOLE_FIELD_CHARS = 180
UTC_PLUS_8 = timezone(timedelta(hours=8))


def console_enabled() -> bool:
    value = os.environ.get("AGENTIC_DATASET_CONSOLE", "1").strip().lower()
    return value not in ("0", "false", "no", "off")


def run_id() -> str:
    return datetime.now(UTC_PLUS_8).strftime("%y-%m-%d-%H-%M")


def ensure_run_log_root(output_root: Path) -> Path:
    env_key = "AGENTIC_DATASET_LOG_ROOT"
    existing = os.environ.get(env_key)
    if existing:
        root = Path(existing)
    else:
        base = output_root / "log" / run_id()
        root = base
        suffix = 2
        while root.exists():
            root = base.with_name(f"{base.name}-{suffix}")
            suffix += 1
        os.environ[env_key] = str(root)
        latest = output_root / "log" / "latest"
        latest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if latest.is_symlink() or latest.exists():
                latest.unlink()
            latest.symlink_to(root, target_is_directory=True)
        except OSError:
            # Symlink creation can fail on some filesystems; keep a plain marker.
            (latest.parent / "latest.txt").write_text(str(root) + "\n", encoding="utf-8")
    root.mkdir(parents=True, exist_ok=True)
    return root


def current_log_root(output_root: Path) -> Path:
    return ensure_run_log_root(output_root)


def compact_value(value: Any) -> str:
    if isinstance(value, Path):
        text = str(value)
    elif isinstance(value, (str, int, float, bool)) or value is None:
        text = str(value)
    else:
        text = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
    text = " ".join(text.split())
    if len(text) > MAX_CONSOLE_FIELD_CHARS:
        return text[: MAX_CONSOLE_FIELD_CHARS - 3] + "..."
    return text


def console_line(record: dict[str, Any]) -> str:
    fields = []
    for key, value in record.items():
        if key in RESERVED_FIELDS:
            continue
        fields.append(f"{key}={compact_value(value)}")
        if len(fields) >= 6:
            break
    suffix = f" {' '.join(fields)}" if fields else ""
    return f"[{record['level']}] {record['stage']}: {record['message']}{suffix}"


def timestamped_console_line(record: dict[str, Any]) -> str:
    return f"{record['time']} {console_line(record)}"


class StageLogger:
    def __init__(self, root: Path, stage: str) -> None:
        self.root = root
        self.stage = stage
        for level in LEVELS:
            (self.root / level).mkdir(parents=True, exist_ok=True)

    def trace(self, message: str, **fields: Any) -> None:
        self._write("trace", message, fields)

    def warn(self, message: str, **fields: Any) -> None:
        self._write("warn", message, fields)

    def error(self, message: str, **fields: Any) -> None:
        self._write("error", message, fields)

    def _write(self, level: str, message: str, fields: dict[str, Any]) -> None:
        safe_fields = {}
        for key, value in fields.items():
            out_key = f"field_{key}" if key in RESERVED_FIELDS else key
            safe_fields[out_key] = value
        record = {
            "time": datetime.now(UTC_PLUS_8).strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            "level": level,
            "stage": self.stage,
            "message": message,
            **safe_fields,
        }
        path = self.root / level / f"{self.stage}.jsonl"
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        run_log = self.root / "run.log"
        with run_log.open("a", encoding="utf-8") as f:
            f.write(timestamped_console_line(record) + "\n")
        if console_enabled():
            print(console_line(record), file=sys.stderr, flush=True)


def get_logger(output_root: Path, stage: str) -> StageLogger:
    return StageLogger(current_log_root(output_root), stage)
