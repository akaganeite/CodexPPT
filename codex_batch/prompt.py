from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .paths import requested_binary_to_actual


def build_prompt(
    template_path: Path,
    cve: str,
    metadata: Any,
    binaries: list[str],
    target_dir: Path,
    opt: str,
    safe_objdump_helper: str,
) -> str:
    actual_map = {b: requested_binary_to_actual(b, opt) for b in binaries}
    payload = {
        "cve": cve,
        "metadata": metadata,
        "requested_binaries": binaries,
        "binary_resolution": actual_map,
        "target_dir": str(target_dir),
        "optimization": opt,
    }
    variables = {
        "SAFE_OBJDUMP_HELPER": safe_objdump_helper,
        "TASK_PAYLOAD_JSON": json.dumps(payload, indent=2, ensure_ascii=False),
    }
    return render_template(template_path.read_text(encoding="utf-8"), variables)


def render_template(template: str, variables: dict[str, str]) -> str:
    for key, value in variables.items():
        template = template.replace("{{" + key + "}}", value)
    return template
