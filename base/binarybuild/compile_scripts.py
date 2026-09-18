from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from builder.config import BuildConfig
from builder.logging import StageLogger
from utils.codex_exec import run_codex_exec_json
from utils.io import write_text
from utils.paths import ROOT


SCHEMA = ROOT / "schemas" / "compile_script_result.schema.json"


def script_path_for_project(project: str) -> Path:
    return ROOT / "binarybuild" / "compile" / f"{project}.py"


def spec_path_for_project(project: str) -> Path:
    return ROOT / "binarybuild" / "compile" / f"{project}.spec.md"


def load_compile_script(project: str) -> Any | None:
    path = script_path_for_project(project)
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location(f"agentic_compile_{project}", path)
    if not spec or not spec.loader:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        return None
    return module


def script_supports_architecture(config: BuildConfig) -> bool:
    """Require explicit adapter opt-in before using an ARM script locally."""
    script = script_path_for_project(config.project)
    if not script.exists():
        return False
    if config.architecture == "x86_64":
        return True
    module = load_compile_script(config.project)
    if module is None:
        return False
    checker = getattr(module, "supports_architecture", None)
    if callable(checker):
        try:
            return bool(checker(config.architecture))
        except Exception:
            return False
    supported = getattr(module, "SUPPORTED_ARCHITECTURES", ())
    return config.architecture in supported


def spec_supports_architecture(config: BuildConfig) -> bool:
    """Require the human/agent-facing adapter map to document ARM support too."""
    if config.architecture == "x86_64":
        return True
    path = spec_path_for_project(config.project)
    try:
        text = path.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False
    return "aarch64" in text or "arm64" in text


def render_script_prompt(config: BuildConfig, stage: str, tasks: list[dict], failure_context: list[dict] | None = None) -> str:
    script_path = script_path_for_project(config.project)
    spec_path = spec_path_for_project(config.project)
    existing_spec = spec_path.read_text(encoding="utf-8", errors="replace") if spec_path.exists() else ""
    existing = script_path.read_text(encoding="utf-8", errors="replace") if script_path.exists() else ""
    return f"""Create or repair the reusable compile script for this project.

Project:
- name: {config.project}
- source repo: {config.repo}
- output root: {config.output}
- compile script path: {script_path}
- compile script spec path: {spec_path}
- compiler: {config.compiler}
- opt: {config.opt}
- architecture/toolchain contract: {json.dumps(config.toolchain.command_details(), ensure_ascii=False)}
- stage needing compile support: {stage}

Batch tasks:
{json.dumps(tasks, ensure_ascii=False, indent=2)[:90000]}

Failure context from the previous scripted attempt:
{json.dumps(failure_context or [], ensure_ascii=False, indent=2)[:60000]}

Existing compile script spec:
```markdown
{existing_spec[:80000]}
```

Existing compile script:
```python
{existing[:120000]}
```

Requirements:
1. If the spec exists, read it first and use it as the map of the adapter. Inspect the Python source only for the functions you need to change.
2. Edit or create the compile script at the exact script path above.
3. The script must be reusable for future incremental builds.
4. Do not compile by modifying the user's source repo checkout directly. Use git worktree or temp/build dirs under the output root.
5. Provide these Python-callable APIs:
   - compile_commit(config, ref, stage, log, profile="static")
   - choose_binary(worktree, functions, preferred="", profile="static")
   - find_binary_by_name(worktree, binary_name, profile="static")
   - copy_binary(src, dest)
   - target_filename(project, version, binary_name, compiler="", opt="")
   Existing builder code will call these APIs.
6. For OpenSSL you may keep compile_openssl_commit as an internal alias, but compile_commit must exist.
7. Make the script robust to old release build differences. Try alternate configure/build commands when needed.
8. If you change project-specific compile behavior or add/remove functions, update the spec file at the exact spec path above.
9. Keep successful detailed build logs removable by config.cleanup_build_logs; keep failure logs.
10. Declare explicit architecture support in the adapter using either SUPPORTED_ARCHITECTURES or supports_architecture(architecture). Document the same capability in the spec file, naming `aarch64` when it is supported. Existing x86_64 behavior must remain supported.
11. For AArch64, use only the central config.toolchain fields: CC/CXX, AR/RANLIB/NM/OBJDUMP/OBJCOPY/STRIP, configure --host, and compiler flags. Do not silently fall back to native tools or native configure defaults. Use the project-appropriate cross configure/build settings.
12. For AArch64, validate every copied artifact with readelf (or the central toolchain readelf) and reject anything whose ELF Machine is not AArch64.
13. Derive target output names from config.target_binary_name so x86 names stay unchanged and AArch64 names retain the aarch64 prefix. Update target_filename if the adapter exposes it and it would otherwise lose architecture.
14. Return JSON only according to the schema. Do not include prose outside JSON.
"""


def ensure_compile_script(config: BuildConfig, stage: str, tasks: list[dict], log: StageLogger, failure_context: list[dict] | None = None) -> bool:
    script_path = script_path_for_project(config.project)
    spec_path = spec_path_for_project(config.project)
    needs_architecture_repair = not script_supports_architecture(config) or not spec_supports_architecture(config)
    if script_path.exists() and not failure_context and not needs_architecture_repair:
        log.trace("using existing compile script", project=config.project, script=str(script_path), stage=stage)
        return True

    codex_dir = config.codex_dir / "compile_scripts"
    codex_dir.mkdir(parents=True, exist_ok=True)
    suffix = "repair" if failure_context or script_path.exists() else "create"
    stem = f"{config.project}-{config.architecture}-{stage}-{suffix}"
    prompt_path = codex_dir / f"{stem}.prompt.md"
    result_path = codex_dir / f"{stem}.result.json"
    events_path = codex_dir / f"{stem}.events.jsonl"
    try:
        spec_before = spec_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        spec_before = ""
    context = list(failure_context or [])
    if needs_architecture_repair:
        context.append(
            {
                "kind": "architecture_capability",
                "architecture": config.architecture,
                "message": "The adapter and spec must explicitly declare support for this architecture.",
            }
        )
    write_text(prompt_path, render_script_prompt(config, stage, tasks, failure_context=context))
    log.trace(
        "running codex compile script task",
        project=config.project,
        stage=stage,
        architecture=config.architecture,
        script=str(script_path),
        repair=bool(context),
    )

    try:
        result = run_codex_exec_json(
            prompt_path=prompt_path,
            output_path=result_path,
            json_events_path=events_path,
            schema_path=SCHEMA,
            codex_model=config.codex_model,
            codex_sandbox=config.codex_sandbox,
            add_dirs=[config.repo, config.output, ROOT],
            timeout=7200,
        )
    except Exception as exc:
        log.error("codex compile script task failed", project=config.project, stage=stage, error=str(exc))
        return False
    try:
        spec_after = spec_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        spec_after = ""
    spec_updated = not needs_architecture_repair or spec_after != spec_before
    ok = (
        result.get("status") in ("ok", "partial")
        and script_supports_architecture(config)
        and spec_supports_architecture(config)
        and spec_updated
    )
    if ok:
        log.trace("compile script ready", project=config.project, stage=stage, spec_updated=spec_updated, result=result)
    else:
        log.error("compile script not produced", project=config.project, stage=stage, spec_updated=spec_updated, result=result)
    return ok
