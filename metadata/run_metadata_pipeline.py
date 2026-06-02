#!/usr/bin/env python3
"""Run the metadata preparation pipeline for one project."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DATASET_ROOT = Path("/home/zhangxb/patch/related-works/CVE-Dataset/New")
TARGET_ROOT = Path("/home/zhangxb/patch/related-works/CVE-Dataset/target")


@dataclass
class Step:
    name: str
    status: str
    command: list[str]
    seconds: float = 0.0
    returncode: int | None = None
    log_path: Path | None = None
    note: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build project JSON, source metadata, behavior metadata, and a report.")
    parser.add_argument("--project", required=True, help="Project name, e.g. curl.")
    parser.add_argument("--dataset-root", type=Path, default=DATASET_ROOT)
    parser.add_argument("--repo-path", type=Path, default=None, help="Git repo path for project_source_analysis.py.")
    parser.add_argument("--output-dir", type=Path, default=None, help="Defaults to metadata/<project>.")
    parser.add_argument("--cve", action="append", default=[], help="Optional CVE filter; repeatable.")
    parser.add_argument("--limit", type=int, default=0, help="Optional max CVEs to process.")
    parser.add_argument("--strict-initial", action="store_true", help="Fail initial build on missing cveinfo or diff.")
    parser.add_argument(
        "--behavior-mode",
        choices=["auto", "run", "dry-run", "skip"],
        default="auto",
        help="auto runs DeepSeek only when DEEPSEEK_API_KEY is already visible; otherwise dry-run.",
    )
    parser.add_argument("--resume-behavior", action="store_true", default=True)
    parser.add_argument("--no-resume-behavior", action="store_false", dest="resume_behavior")
    parser.add_argument("--env-file", type=Path, default=None)
    parser.add_argument("--deepseek-model", default="")
    parser.add_argument("--deepseek-base-url", default="")
    parser.add_argument("--api-timeout", type=int, default=300)
    parser.add_argument("--sleep", type=float, default=0.0)
    parser.add_argument("--continue-on-error", action="store_true")
    return parser.parse_args()


def shell_join(cmd: list[str]) -> str:
    return " ".join(shlex.quote(str(x)) for x in cmd)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def run_step(name: str, cmd: list[str], log_path: Path, cwd: Path) -> Step:
    started = time.time()
    proc = subprocess.run(
        [str(x) for x in cmd],
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    seconds = time.time() - started
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(proc.stdout, encoding="utf-8", errors="replace")
    return Step(name=name, status="ok" if proc.returncode == 0 else "failed", command=cmd, seconds=seconds, returncode=proc.returncode, log_path=log_path)


def skipped_step(name: str, note: str) -> Step:
    return Step(name=name, status="skipped", command=[], note=note)


def is_git_repo(path: Path | None) -> bool:
    if path is None:
        return False
    proc = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def infer_repo_path(project: str, explicit: Path | None) -> Path | None:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit.expanduser().resolve())
    candidates.extend(
        [
            TARGET_ROOT / project,
            TARGET_ROOT / f"{project}-gdb",
            TARGET_ROOT / f"{project}-new",
            TARGET_ROOT / f"{project}.pre-extrepo-move",
        ]
    )
    for path in candidates:
        if is_git_repo(path):
            return path
    return None


def add_filters(cmd: list[str], cves: list[str], limit: int) -> list[str]:
    out = list(cmd)
    for cve in cves:
        out.extend(["--cve", cve])
    if limit:
        out.extend(["--limit", str(limit)])
    return out


def initial_stats(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = load_json(path)
    return data if isinstance(data, dict) else {}


def source_stats(full_path: Path, min_path: Path) -> dict[str, Any]:
    stats: dict[str, Any] = {}
    if full_path.exists():
        full = load_json(full_path)
        if isinstance(full, dict):
            stats["cve_count"] = full.get("cve_count", 0)
            cves = full.get("cves", {})
            if isinstance(cves, dict):
                statuses: dict[str, int] = {}
                function_count = 0
                for item in cves.values():
                    for analysis in item.get("function_analyses", []) if isinstance(item, dict) else []:
                        status = analysis.get("analysis_status", "unknown") if isinstance(analysis, dict) else "unknown"
                        statuses[status] = statuses.get(status, 0) + 1
                        function_count += 1
                stats["function_count"] = function_count
                stats["analysis_statuses"] = statuses
    if min_path.exists():
        compact = load_json(min_path)
        if isinstance(compact, dict):
            stats["compact_cve_count"] = len(compact)
    return stats


def behavior_stats(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    analyzed = 0
    errors = 0
    for item in data.values():
        if not isinstance(item, dict):
            continue
        if item.get("root_cause_analysis") and item.get("patch_intent_analysis"):
            analyzed += 1
        if item.get("behavior_analysis_error"):
            errors += 1
    return {"cve_count": len(data), "analyzed": analyzed, "errors": errors}


def render_report(
    *,
    project: str,
    output_dir: Path,
    repo_path: Path | None,
    files: dict[str, Path],
    steps: list[Step],
) -> str:
    lines: list[str] = []
    lines.append(f"# {project} metadata pipeline run")
    lines.append("")
    lines.append("## 产物")
    for label, path in files.items():
        exists = "存在" if path.exists() or label == "report" else "未生成"
        lines.append(f"- `{label}`: `{path}` ({exists})")
    lines.append("")
    lines.append("## 输入")
    lines.append(f"- project: `{project}`")
    lines.append(f"- output_dir: `{output_dir}`")
    lines.append(f"- repo_path: `{repo_path or ''}`")
    lines.append("")
    lines.append("## 步骤")
    for step in steps:
        lines.append(f"### {step.name}")
        lines.append(f"- status: `{step.status}`")
        if step.returncode is not None:
            lines.append(f"- returncode: `{step.returncode}`")
        if step.seconds:
            lines.append(f"- seconds: `{step.seconds:.2f}`")
        if step.log_path:
            lines.append(f"- log: `{step.log_path}`")
        if step.note:
            lines.append(f"- note: {step.note}")
        if step.command:
            lines.append("")
            lines.append("```bash")
            lines.append(shell_join(step.command))
            lines.append("```")
        lines.append("")

    istats = initial_stats(files["initial_stats"])
    if istats:
        lines.append("## 初始 JSON 统计")
        for key in (
            "input_source_diff_cves",
            "selected_cves",
            "emitted_cves",
            "total_functions",
            "diff_files_found",
            "diff_files_missing",
            "cveinfo_found",
            "cveinfo_missing",
            "functions_with_file",
            "functions_without_file",
        ):
            lines.append(f"- {key}: `{istats.get(key, 0)}`")
        for key, count in sorted((istats.get("change_types") or {}).items()):
            lines.append(f"- change_type.{key}: `{count}`")
        for key, count in sorted((istats.get("inference_methods") or {}).items()):
            lines.append(f"- inferred_by.{key}: `{count}`")
        lines.append("")

    sstats = source_stats(files["source_full"], files["source_min"])
    if sstats:
        lines.append("## 源码分析统计")
        lines.append(f"- cve_count: `{sstats.get('cve_count', sstats.get('compact_cve_count', 0))}`")
        lines.append(f"- function_count: `{sstats.get('function_count', 0)}`")
        statuses = sstats.get("analysis_statuses", {})
        if isinstance(statuses, dict):
            for status, count in sorted(statuses.items()):
                lines.append(f"- analysis_status.{status}: `{count}`")
        lines.append("")

    bstats = behavior_stats(files["behavior"])
    if bstats:
        lines.append("## DeepSeek 行为分析统计")
        lines.append(f"- cve_count: `{bstats.get('cve_count', 0)}`")
        lines.append(f"- analyzed: `{bstats.get('analyzed', 0)}`")
        lines.append(f"- errors: `{bstats.get('errors', 0)}`")
        lines.append("")

    lines.append("## 说明")
    lines.append("- 第一步生成的 project.json 是 `project_source_analysis.py` 的输入，默认只保留 diff 文件路径，不内嵌 hunk 文本。")
    lines.append("- 初始 JSON 不提供函数源码；后续源码分析脚本会重新解析 diff，并基于 git commit 补充 reduced source context。")
    lines.append("- 如果 `repo_path` 为空或不是 git 仓库，源码分析会跳过；需要提供可 `git show <commit>:<file>` 的项目仓库。")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    project = args.project
    output_dir = (args.output_dir or ROOT / project).resolve()
    log_dir = output_dir / "logs"
    output_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "initial_project_json": output_dir / f"{project}.json",
        "initial_stats": output_dir / f"{project}_initial_build_stats.json",
        "source_full": output_dir / f"{project}_project_source_analysis.full.json",
        "source_min": output_dir / f"{project}_project_source_analysis.min.json",
        "behavior": output_dir / f"{project}_project_source_analysis.behavior.json",
        "report": output_dir / f"{project}_metadata_pipeline.md",
    }

    steps: list[Step] = []

    initial_cmd = [
        sys.executable,
        str(ROOT / "build_initial_project_json.py"),
        "--project",
        project,
        "--dataset-root",
        str(args.dataset_root),
        "--output",
        str(files["initial_project_json"]),
        "--stats-output",
        str(files["initial_stats"]),
    ]
    if args.strict_initial:
        initial_cmd.append("--strict")
    initial_cmd = add_filters(initial_cmd, args.cve, args.limit)
    steps.append(run_step("1. build_initial_project_json", initial_cmd, log_dir / "01_build_initial_project_json.log", ROOT.parent))

    repo_path = infer_repo_path(project, args.repo_path)
    stop_pipeline = steps[-1].status != "ok" and not args.continue_on_error
    if stop_pipeline:
        steps.append(skipped_step("2. project_source_analysis", "上一步失败，未设置 --continue-on-error。"))
    elif not repo_path:
        steps.append(
            skipped_step(
                "2. project_source_analysis",
                "未找到可用 git repo；请传入 --repo-path，例如 /path/to/curl.git checkout。",
            )
        )
    else:
        source_cmd = [
            sys.executable,
            str(ROOT / "project_source_analysis.py"),
            "--input",
            str(files["initial_project_json"]),
            "--project",
            project,
            "--repo-path",
            str(repo_path),
            "--output-full",
            str(files["source_full"]),
            "--output-min",
            str(files["source_min"]),
        ]
        source_cmd = add_filters(source_cmd, args.cve, args.limit)
        steps.append(run_step("2. project_source_analysis", source_cmd, log_dir / "02_project_source_analysis.log", ROOT.parent))

    if steps[-1].status == "failed" and not args.continue_on_error:
        steps.append(skipped_step("3. generate_behavior_analysis_deepseek", "上一步失败，未设置 --continue-on-error。"))
    elif args.behavior_mode == "skip":
        steps.append(skipped_step("3. generate_behavior_analysis_deepseek", "--behavior-mode skip"))
    elif not files["source_min"].exists():
        steps.append(skipped_step("3. generate_behavior_analysis_deepseek", "compact source metadata 不存在。"))
    else:
        behavior_mode = args.behavior_mode
        if behavior_mode == "auto" and not os.environ.get("DEEPSEEK_API_KEY"):
            behavior_mode = "dry-run"

        behavior_cmd = [
            sys.executable,
            str(ROOT / "generate_behavior_analysis_deepseek.py"),
            "--input",
            str(files["source_min"]),
            "--output",
            str(files["behavior"]),
        ]
        if args.resume_behavior:
            behavior_cmd.append("--resume")
        if args.env_file:
            behavior_cmd.extend(["--env-file", str(args.env_file)])
        if args.deepseek_model:
            behavior_cmd.extend(["--model", args.deepseek_model])
        if args.deepseek_base_url:
            behavior_cmd.extend(["--base-url", args.deepseek_base_url])
        if args.api_timeout:
            behavior_cmd.extend(["--api-timeout", str(args.api_timeout)])
        if args.sleep:
            behavior_cmd.extend(["--sleep", str(args.sleep)])
        if behavior_mode == "dry-run":
            behavior_cmd.append("--dry-run")
        behavior_cmd = add_filters(behavior_cmd, args.cve, args.limit)
        steps.append(run_step("3. generate_behavior_analysis_deepseek", behavior_cmd, log_dir / "03_generate_behavior_analysis_deepseek.log", ROOT.parent))

    report = render_report(project=project, output_dir=output_dir, repo_path=repo_path, files=files, steps=steps)
    write_text(files["report"], report)
    print(f"wrote report: {files['report']}")

    failed = [step for step in steps if step.status == "failed"]
    if failed and not args.continue_on_error:
        return failed[-1].returncode or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
