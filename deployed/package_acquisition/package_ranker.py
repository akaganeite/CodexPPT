"""Build closed-world package-ranking tasks and validate DeepSeek output."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from ..candidate_discovery.metadata import CveMetadata
from ..config import ProjectConfig
from ..io_utils import write_json
from ..system_utils import safe_token
from .deepseek_client import DEFAULT_LLM_CONFIG, DeepSeekConfig, call_deepseek, load_llm_config
from .package_hints import metadata_function_files, package_matches_component, package_matches_hint, source_component_hints


def rank_selected_packages(
    selection_result: dict[str, Any],
    metadata: CveMetadata,
    project: ProjectConfig,
    *,
    output: Path,
    config_path: Path | None = None,
    base_binary_hints: list[str] | None = None,
    refresh: bool = False,
    log: Callable[[str], None] | None = None,
    transport: Callable[[DeepSeekConfig, str, str], tuple[dict[str, Any], dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    selected = selection_result.get("selected") or {}
    candidate_source = selection_result.get("candidate_pool") or selected
    families = candidate_families(candidate_source)
    config = load_llm_config(config_path)
    function_files = metadata_function_files(metadata)
    tasks = []
    for function in metadata.functions:
        task = build_ranking_task(
            selection_result,
            function=function,
            source_file=function_files.get(function, ""),
            project=project,
            families=families,
            base_binary_hints=base_binary_hints or [],
        )
        tasks.append(
            rank_task(
                task,
                config=config,
                cache_root=output / "state" / "package_ranking",
                refresh=refresh,
                log=log,
                transport=transport,
            )
        )
    return {
        "schema": "ubuntu-package-ranking-v1",
        "cve_id": selection_result.get("cve_id") or metadata.cve_id,
        "project": project.project,
        "source_package": project.source_package,
        "series": selected.get("series") or "",
        "source_versions": selected_source_versions(candidate_source),
        "config": config.public_json(),
        "candidate_families": families,
        "tasks": tasks,
        "status": summarize_ranking_status(tasks),
    }


def candidate_families(selected: dict[str, Any]) -> list[dict[str, Any]]:
    selected_rows = [
        ("vuln", item)
        for item in selected.get("vulnerable") or []
    ] + [
        ("patch", item)
        for item in selected.get("patch") or []
    ]
    all_version_keys = [
        (label, str(item.get("series") or ""), str(item.get("source_version") or ""))
        for label, item in selected_rows
    ]
    # Keep actual package names per publication while grouping ABI-renamed
    # packages such as libavcodec58/libavcodec59 into one logical family.
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for label, item in selected_rows:
        availability = item.get("binary_availability") or {}
        candidate_pairs = sorted(
            availability.get("runtime_debug_pairs") or [],
            key=lambda pair: 0 if pair.get("match") == "exact_package_name" else 1,
        )
        for pair in candidate_pairs:
            runtime = dict(pair.get("runtime") or {})
            debug = dict(pair.get("debug") or {})
            runtime_package = str(runtime.get("package") or "")
            debug_package = str(debug.get("package") or "")
            if not runtime_package or not debug_package:
                continue
            runtime_family = logical_package_family(runtime_package)
            debug_family = logical_package_family(debug_package)
            key = (runtime_family, debug_family)
            family = by_key.setdefault(
                key,
                {
                    "candidate_id": candidate_id(runtime_family, debug_family),
                    "runtime_package": runtime_family,
                    "debug_package": debug_family,
                    "package_variants": [],
                    "versions": [],
                },
            )
            version = str(item.get("source_version") or "")
            version_key = (label, str(item.get("series") or ""), version)
            if any(
                (existing.get("label"), existing.get("series"), existing.get("source_version")) == version_key
                for existing in family["versions"]
            ):
                continue
            variant = {"runtime_package": runtime_package, "debug_package": debug_package}
            if variant not in family["package_variants"]:
                family["package_variants"].append(variant)
            family["versions"].append(
                {
                    "source_version": version,
                    "label": label,
                    "days_from_fix": item.get("days_from_fix"),
                    "series": item.get("series") or selected.get("series") or "",
                    "pocket": item.get("pocket") or "",
                    "component": item.get("component") or "",
                    "source_publication": item.get("source_publication") or {},
                    "source_validation": item.get("source_validation") or {},
                    "runtime": runtime,
                    "debug": debug,
                }
            )
    output = []
    for family in by_key.values():
        family["versions"].sort(
            key=lambda item: all_version_keys.index((item["label"], item["series"], item["source_version"]))
            if (item["label"], item["series"], item["source_version"]) in all_version_keys
            else 999
        )
        covered = {(item["label"], item["series"], item["source_version"]) for item in family["versions"]}
        family["coverage_count"] = len(covered)
        family["required_version_count"] = len(set(all_version_keys))
        family["available_versions"] = [key[2] for key in all_version_keys if key in covered]
        family["missing_versions"] = [key[2] for key in all_version_keys if key not in covered]
        output.append(family)
    return sorted(
        output,
        key=lambda item: (-item["coverage_count"], item["runtime_package"], item["debug_package"]),
    )


def build_ranking_task(
    selection_result: dict[str, Any],
    *,
    function: str,
    source_file: str,
    project: ProjectConfig,
    families: list[dict[str, Any]],
    base_binary_hints: list[str],
) -> dict[str, Any]:
    selected = selection_result.get("selected") or {}
    components = source_component_hints([source_file])
    ranked = deterministic_family_order(
        families,
        project=project,
        source_components=components,
        base_binary_hints=base_binary_hints,
    )
    return {
        "schema": "ubuntu-package-ranking-task-v1",
        "cve_id": selection_result.get("cve_id") or "",
        "project": project.project,
        "source_package": project.source_package,
        "ubuntu_series": selected.get("series") or "",
        "ubuntu_release": selected.get("ubuntu_release") or "",
        "source_versions": selected_source_versions(selection_result.get("candidate_pool") or selected),
        "function": function,
        "source_file": source_file,
        "source_components": components,
        "base_binary_hints": list(dict.fromkeys(base_binary_hints)),
        "candidates": [compact_family(item) for item in ranked],
    }


def deterministic_family_order(
    families: list[dict[str, Any]],
    *,
    project: ProjectConfig,
    source_components: list[str],
    base_binary_hints: list[str],
) -> list[dict[str, Any]]:
    exact_order = {name: index for index, name in enumerate(project.binary_packages.exact)}
    output = []
    for family in families:
        runtime = str(family.get("runtime_package") or "")
        debug = str(family.get("debug_package") or "")
        variants = family.get("package_variants") or []
        runtime_names = list(dict.fromkeys([runtime, *(str(item.get("runtime_package") or "") for item in variants)]))
        debug_names = list(dict.fromkeys([debug, *(str(item.get("debug_package") or "") for item in variants)]))
        score = int(family.get("coverage_count") or 0) * 1000
        reasons = [f"available in {family.get('coverage_count', 0)}/{family.get('required_version_count', 0)} selected versions"]
        exact_matches = [name for name in runtime_names if name in exact_order]
        if exact_matches:
            score += max(1, 200 - min(exact_order[name] for name in exact_matches))
            reasons.append("project exact runtime package hint")
        elif any(project.runtime_name_matches(name) for name in runtime_names):
            score += 60
            reasons.append("project runtime package rule")
        if any(project.debug_name_matches(name) for name in debug_names):
            score += 40
            reasons.append("project debug package rule")
        matched_components = [
            item for item in source_components if any(package_matches_component(name, item) for name in runtime_names)
        ]
        if matched_components:
            score += 160
            reasons.append(f"matches source component: {', '.join(matched_components)}")
        matched_hints = [item for item in base_binary_hints if any(package_matches_hint(name, item) for name in runtime_names)]
        if matched_hints:
            score += 25
            reasons.append(f"matches base binary hint: {', '.join(matched_hints)}")
        output.append({**family, "deterministic_score": score, "deterministic_reasons": reasons})
    return sorted(
        output,
        key=lambda item: (-item["deterministic_score"], item["runtime_package"], item["debug_package"]),
    )


def rank_task(
    task: dict[str, Any],
    *,
    config: DeepSeekConfig,
    cache_root: Path,
    refresh: bool,
    log: Callable[[str], None] | None,
    transport: Callable[[DeepSeekConfig, str, str], tuple[dict[str, Any], dict[str, Any]]] | None,
) -> dict[str, Any]:
    prompt = render_ranking_prompt(task)
    task_hash = content_hash({"task": task, "model": config.model, "prompt_version": "v1"})
    task_dir = cache_root / safe_token(str(task.get("cve_id") or "unknown")) / safe_token(str(task.get("function") or "function"))
    task_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = task_dir / f"{task_hash}.prompt.md"
    request_path = task_dir / f"{task_hash}.request.json"
    result_path = task_dir / f"{task_hash}.result.json"
    prompt_path.write_text(prompt, encoding="utf-8")
    write_json(request_path, task)
    if result_path.exists() and not refresh:
        try:
            cached = json.loads(result_path.read_text(encoding="utf-8"))
            if cached.get("task_hash") == task_hash:
                return cached
        except json.JSONDecodeError:
            pass
    deterministic_ids = [str(item.get("candidate_id") or "") for item in task.get("candidates") or []]
    api_key, key_source = config.resolved_api_key()
    if not config.enabled or not api_key:
        reason = "LLM ranking disabled" if not config.enabled else "DeepSeek API key unavailable"
        result = normalized_ranking_result(
            task,
            {},
            task_hash=task_hash,
            status="deterministic_fallback",
            model=config.model,
            warnings=[reason],
            deterministic_ids=deterministic_ids,
            response_meta={"api_key_source": key_source},
        )
        write_json(result_path, result)
        return result
    if log:
        log(f"package-rank start cve={task.get('cve_id')} function={task.get('function')} candidates={len(deterministic_ids)}")
    try:
        raw_result, response_meta = (transport or call_deepseek)(config, api_key, prompt)
        result = normalized_ranking_result(
            task,
            raw_result,
            task_hash=task_hash,
            status="llm_ranked",
            model=str(response_meta.get("model") or config.model),
            warnings=[],
            deterministic_ids=deterministic_ids,
            response_meta={**response_meta, "api_key_source": key_source},
        )
    except Exception as exc:
        result = normalized_ranking_result(
            task,
            {},
            task_hash=task_hash,
            status="llm_failed_fallback",
            model=config.model,
            warnings=[str(exc)],
            deterministic_ids=deterministic_ids,
            response_meta={"api_key_source": key_source},
        )
    write_json(result_path, result)
    if log:
        log(
            f"package-rank done cve={task.get('cve_id')} function={task.get('function')} "
            f"status={result['status']} first={result['ranking'][0]['candidate_id'] if result['ranking'] else '-'}"
        )
    return result


def render_ranking_prompt(task: dict[str, Any]) -> str:
    return f"""Rank the supplied Ubuntu runtime/debug package candidate families for the changed function.

The package family should cover enough candidate source versions to form the largest available balanced set, up to 3v3. Labels are intentionally omitted so package selection cannot depend on vuln/patch status. Use the source path, function, project, Ubuntu series, base binary hints, package names, and version coverage. Candidate IDs and package names are closed-world inputs.

Return JSON exactly in this shape:
{{
  "ranking": [
    {{
      "candidate_id": "one input candidate_id",
      "expected_elf": ["likely ELF basename or SONAME"],
      "confidence": "high|medium|low",
      "reason": "brief technical reason"
    }}
  ]
}}

Rules:
1. Include every input candidate exactly once.
2. Never create a candidate ID or package name.
3. Prefer candidates with broad coverage across the supplied candidate pool.
4. Rank the package expected to contain compiled code from source_file/function, not merely a similarly named CLI package.
5. Do not claim that ranking proves function presence; downloads, Build-ID matching, and ELF inspection will verify it.

Task JSON:
```json
{json.dumps(task, indent=2, ensure_ascii=False)}
```
"""


def normalized_ranking_result(
    task: dict[str, Any],
    raw_result: dict[str, Any],
    *,
    task_hash: str,
    status: str,
    model: str,
    warnings: list[str],
    deterministic_ids: list[str],
    response_meta: dict[str, Any],
) -> dict[str, Any]:
    allowed = {str(item.get("candidate_id") or ""): item for item in task.get("candidates") or []}
    ranking = []
    seen = set()
    # Treat the candidate set as closed-world: model-created IDs never enter the pipeline.
    for item in raw_result.get("ranking") or []:
        if not isinstance(item, dict):
            continue
        candidate = str(item.get("candidate_id") or "")
        if candidate not in allowed or candidate in seen:
            if candidate:
                warnings.append(f"ignored unknown or duplicate candidate_id: {candidate}")
            continue
        seen.add(candidate)
        expected = item.get("expected_elf") or []
        if isinstance(expected, str):
            expected = [expected]
        ranking.append(
            {
                "candidate_id": candidate,
                "runtime_package": allowed[candidate].get("runtime_package") or "",
                "debug_package": allowed[candidate].get("debug_package") or "",
                "expected_elf": [str(value) for value in expected if str(value).strip()],
                "confidence": normalize_confidence(item.get("confidence")),
                "reason": str(item.get("reason") or ""),
                "source": "llm" if status == "llm_ranked" else "deterministic",
            }
        )
    for candidate in deterministic_ids:
        if candidate in seen or candidate not in allowed:
            continue
        ranking.append(
            {
                "candidate_id": candidate,
                "runtime_package": allowed[candidate].get("runtime_package") or "",
                "debug_package": allowed[candidate].get("debug_package") or "",
                "expected_elf": [],
                "confidence": "low",
                "reason": "; ".join(allowed[candidate].get("deterministic_reasons") or ["deterministic fallback order"]),
                "source": "deterministic",
            }
        )
    return {
        "schema": "ubuntu-package-ranking-result-v1",
        "task_hash": task_hash,
        "cve_id": task.get("cve_id") or "",
        "function": task.get("function") or "",
        "source_file": task.get("source_file") or "",
        "status": status,
        "model": model,
        "ranking": ranking,
        "warnings": warnings,
        "response": response_meta,
    }


def selected_source_versions(selected: dict[str, Any]) -> list[str]:
    return [
        str(item.get("source_version") or "")
        for item in [*(selected.get("vulnerable") or []), *(selected.get("patch") or [])]
        if item.get("source_version")
    ]


def compact_family(family: dict[str, Any]) -> dict[str, Any]:
    return {
        key: family.get(key)
        for key in (
            "candidate_id",
            "runtime_package",
            "debug_package",
            "coverage_count",
            "required_version_count",
            "available_versions",
            "missing_versions",
            "package_variants",
            "deterministic_score",
            "deterministic_reasons",
        )
    }


def candidate_id(runtime_package: str, debug_package: str) -> str:
    digest = hashlib.sha256(f"{runtime_package}\0{debug_package}".encode("utf-8")).hexdigest()[:12]
    return f"pair_{digest}"


def logical_package_family(package: str) -> str:
    value = re.sub(r"-(?:dbgsym|dbg)$", "", package.strip().lower())
    if value.startswith("lib"):
        value = re.sub(r"[0-9][0-9.]*$", "", value)
    return value or package.strip().lower()


def content_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def normalize_confidence(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in {"high", "medium", "low"} else "low"


def summarize_ranking_status(tasks: list[dict[str, Any]]) -> str:
    statuses = {str(item.get("status") or "") for item in tasks}
    if not tasks:
        return "no_tasks"
    if statuses == {"llm_ranked"}:
        return "llm_ranked"
    if "llm_ranked" in statuses:
        return "partial_llm_ranked"
    if "llm_failed_fallback" in statuses:
        return "llm_failed_fallback"
    return "deterministic_fallback"
