from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .paths import resolve_requested_binary


STATIC_ONLY_POLICY_PATH = Path(__file__).resolve().parent.parent / "prompts" / "static_only_policy.md"

GHIDRA_GUIDANCE = """## Optional Native Ghidra Tools

Six read-only tools are available for the single anonymous `target_binary`:
`ghidra_locate_function`, `ghidra_function_summary`, `ghidra_cfg_slice`,
`ghidra_path_probe`, `ghidra_call_args`, and `ghidra_decompile_slice`.

- Prefer `ghidra_locate_function` for stripped-function localization, then
  verify a candidate with raw instructions, CFG, path, or call-site evidence.
- Candidate scores and recovered pseudocode are navigation aids, not sufficient
  final evidence by themselves.
- `ghidra_decompile_slice` is advisory; a determinate verdict must also cite
  raw instruction, CFG, or P-code-backed observations.
- The tools are bound to the current anonymous binary and cannot inspect other
  files or execute the target.
"""


def build_prompt(
    template_path: Path,
    cve: str,
    metadata: Any,
    binaries: list[str],
    target_dir: Path,
    compiler: str,
    opt: str,
    safe_objdump_helper: str,
    binary_resolution: dict[str, str] | None = None,
    ghidra_enabled: bool = False,
) -> str:
    actual_map = (
        binary_resolution
        if binary_resolution is not None
        else {b: resolve_requested_binary(target_dir, b, compiler, opt) for b in binaries}
    )
    payload = {
        "cve": cve,
        "metadata": metadata,
        "requested_binaries": binaries,
        "binary_resolution": actual_map,
        "target_dir": str(target_dir),
        "compiler": compiler,
        "optimization": opt,
    }
    variables = {
        "SAFE_OBJDUMP_HELPER": safe_objdump_helper,
        "TASK_PAYLOAD_JSON": json.dumps(payload, indent=2, ensure_ascii=False),
    }
    rendered = render_template(template_path.read_text(encoding="utf-8"), variables).rstrip()
    policy = STATIC_ONLY_POLICY_PATH.read_text(encoding="utf-8").strip()
    ghidra = f"\n\n{GHIDRA_GUIDANCE.strip()}" if ghidra_enabled else ""
    return f"{rendered}{ghidra}\n\n{policy}\n"


def render_template(template: str, variables: dict[str, str]) -> str:
    for key, value in variables.items():
        template = template.replace("{{" + key + "}}", value)
    return template
