"""Shared paths, constants, and small JSON/file helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
TOOLS_JSON = ROOT / "tools.json"
SYSTEM_PROMPT = ROOT / "prompts" / "system.txt"
FINAL_RESULT_SCHEMA = ROOT / "schemas" / "final_result.schema.json"
MODEL_CONFIG = ROOT / "model_config.json"

# The backend (base_url, model, reasoning effort, api-key env var) is configured
# entirely in model_config.json - see model_config.py. There are no ambient
# OPENAI_BASE_URL / OPENAI_MODEL / OPENAI_API_KEY env defaults here: the config
# file is the single source of truth for which provider a run talks to. The API
# key is read from the env var named by the chosen profile (or its key file).

# Verdict vocabulary. Determinate verdicts must cite tool-emitted evidence ids.
VERDICTS = ("present", "absent", "not_affected", "inconclusive")
DETERMINATE_STATUSES = {"present", "absent", "not_affected"}
PROVIDER_ERROR_STATUS = "provider_error"


def jdump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)


def compact_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def expand(path: str | Path) -> Path:
    return Path(path).expanduser()


def load_json(path: str | Path) -> Any:
    return json.loads(expand(path).read_text(errors="replace"))


def write_artifact(output_dir: str, name: str, content: str) -> Path | None:
    if not output_dir:
        return None
    out = expand(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / name
    path.write_text(content, encoding="utf-8")
    return path


def compact_lines(lines: list[str], limit: int = 8) -> list[str]:
    return [line.strip() for line in lines if line.strip()][:limit]
