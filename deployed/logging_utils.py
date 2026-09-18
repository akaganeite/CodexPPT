from __future__ import annotations

import sys
import threading
import time
from pathlib import Path


class BuildLogger:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.started = time.time()
        self._lock = threading.Lock()

    def log(self, message: str) -> None:
        line = f"[deployed] {time.time() - self.started:7.1f}s {message}"
        with self._lock:
            print(line, file=sys.stderr, flush=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
