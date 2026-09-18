from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from builder.architecture import normalize_architecture, validate_toolchain
from builder.config import BuildConfig, load_base_config, normalize_testset_strategy
from CVEhunt.cve2diff_codex import run_cve2diff
from CVEhunt.cve_metadata import update_cve_metadata
from builder.db import ProjectDB
from testset.export_stage import export_outputs, export_variant_testset_and_groundtruth
from builder.preprocess import update_git_repo, write_config
from binarybuild.reference_build import run_reference_build
from binarybuild.not_affected_review import run_not_affected_review
from testset.releases_stage import update_releases
from CVEhunt.source_analyzer import run_source_analysis
from binarybuild.target_build import run_target_build
from binarybuild.debug_split import run_debug_split
from testset.testset_stage import select_default_entries
from testset.manifest_stage import (
    align_locked_manifest_exports,
    apply_locked_manifest,
    apply_locked_manifest_reviews,
    manifest_cves,
    validate_locked_manifest_exports,
)
from builder.logging import get_logger
from binarybuild.worktree_cleanup import list_project_worktrees, remove_worktrees
from binarybuild.build_log_cleanup import list_build_logs, remove_existing_build_logs


CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def run_rca_metadata(config: BuildConfig, db: ProjectDB) -> None:
    from RCA.behavior_stage import run_rca_metadata as run

    run(config, db)


def add_build_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("build", help="Run the full agentic dataset build pipeline.")
    parser.add_argument("-p", "--project", required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--db", type=Path, default=None)
    parser.add_argument("--vendor-product", default="", help="vendor:product. Defaults to base/config.json vendor_map.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--latest", type=int, help="Select latest N CVEs.")
    group.add_argument("--cve", action="append", default=[], help="Specific CVE. Repeatable.")
    group.add_argument("--cve-file", type=Path, default=None, help="Read specific CVEs from a file, one CVE id per line.")
    group.add_argument(
        "--testset-manifest",
        type=Path,
        default=None,
        help="Use an authoritative project testset/groundtruth manifest and skip CVE/source discovery.",
    )
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--opt", default="-O0")
    parser.add_argument(
        "--arch",
        type=normalize_architecture,
        default="x86_64",
        help="Target architecture: x86_64 (default) or aarch64; arm64 is an alias.",
    )
    parser.add_argument("--testset-strategy", default="chronical", help="Testset selection strategy. Default: chronical.")
    parser.add_argument("--testset-count", type=int, default=3, help="Number of vuln and patch target releases to select per CVE. Default: 3.")
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--codex-model", default="")
    parser.add_argument("--codex-sandbox", default="danger-full-access", choices=["read-only", "workspace-write", "danger-full-access"])
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_NIST_API_KEY", ""))
    parser.add_argument("--metadata-mode", default="skip", choices=["skip", "source", "behavior"])
    parser.add_argument(
        "--cleanup-worktrees",
        default="success",
        choices=["success", "all", "none"],
        help="Cleanup build worktrees after compile stages. success keeps failed build worktrees for debugging.",
    )
    parser.add_argument(
        "--cleanup-build-logs",
        default="success",
        choices=["success", "all", "none"],
        help="Cleanup detailed configure/make logs after compile stages. success keeps failed build logs for debugging.",
    )
    parser.add_argument("--resume", action="store_true")
    parser.set_defaults(func=handle_build)


def add_cleanup_worktrees_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("cleanup-worktrees", help="Remove build worktrees for an existing output directory.")
    parser.add_argument("-p", "--project", required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--db", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true", help="List worktrees without deleting them.")
    parser.set_defaults(func=handle_cleanup_worktrees)


def add_cleanup_build_logs_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("cleanup-build-logs", help="Remove detailed configure/make logs for an existing output directory.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stage", choices=["reference_build", "target_build"], default=None)
    parser.add_argument("--dry-run", action="store_true", help="List build logs without deleting them.")
    parser.set_defaults(func=handle_cleanup_build_logs)


def add_migrate_db_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("migrate-db", help="Upgrade an existing project SQLite database to the current schema.")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=None)
    parser.set_defaults(func=handle_migrate_db)


def add_select_rq_testset_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "select-rq-testset",
        help="Create a deterministic RQ2/RQ3-stratified PPT subset from existing exports.",
    )
    parser.add_argument("-p", "--project", required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=20, help="Maximum CVEs to select. Default: 20.")
    parser.add_argument(
        "--variant",
        default="",
        help="Export variant to select from, for example gcc-O2. Defaults to canonical, then gcc-O2 if needed.",
    )
    parser.set_defaults(func=handle_select_rq_testset)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agentic dataset builder orchestration helpers.")
    subparsers = parser.add_subparsers(dest="command_name", required=True)
    add_build_parser(subparsers)
    add_cleanup_worktrees_parser(subparsers)
    add_cleanup_build_logs_parser(subparsers)
    add_migrate_db_parser(subparsers)
    add_select_rq_testset_parser(subparsers)
    return parser


def handle_migrate_db(args: argparse.Namespace) -> int:
    db_path = args.db.expanduser().resolve()
    db = ProjectDB(db_path)
    try:
        version = db.conn.execute("PRAGMA user_version").fetchone()[0]
        foreign_keys = db.conn.execute("PRAGMA foreign_keys").fetchone()[0]
        integrity = db.conn.execute("PRAGMA integrity_check").fetchone()[0]
        violations = [tuple(row) for row in db.conn.execute("PRAGMA foreign_key_check")]
        migration = db.conn.execute("SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 1").fetchone()
        report = {
            "database": str(db_path),
            "schema_version": version,
            "foreign_keys": foreign_keys,
            "integrity_check": integrity,
            "foreign_key_violations": violations,
            "migration": dict(migration) if migration else None,
        }
    finally:
        db.close()
    report_path = args.report.expanduser().resolve() if args.report else db_path.with_suffix(".migration.json")
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if integrity == "ok" and not violations and foreign_keys == 1 else 1


def infer_vendor_product(project: str, explicit: str, base_config: dict | None = None) -> str:
    if explicit:
        return explicit
    config = base_config or load_base_config()
    pair = (config.get("vendor_map", {}) or {}).get(project)
    if pair and len(pair) >= 2:
        return f"{pair[0]}:{pair[1]}"
    return f"{project}:{project}"


def validate_cve_ids(cves: list[str], source: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for idx, cve_id in enumerate(cves, start=1):
        if not CVE_ID_RE.fullmatch(cve_id):
            raise ValueError(f"{source}:{idx}: invalid CVE id {cve_id!r}; expected CVE-YYYY-NNNN")
        if cve_id in seen:
            continue
        seen.add(cve_id)
        out.append(cve_id)
    return out


def read_cve_file(path: Path) -> list[str]:
    path = path.expanduser().resolve()
    if not path.exists():
        raise ValueError(f"CVE file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"CVE file is not a regular file: {path}")
    cves: list[str] = []
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line:
            raise ValueError(f"{path}:{line_no}: empty lines are not allowed")
        if raw_line != raw_line.strip():
            raise ValueError(f"{path}:{line_no}: line must contain only a CVE id, without whitespace or extra fields")
        if not CVE_ID_RE.fullmatch(raw_line):
            raise ValueError(f"{path}:{line_no}: invalid CVE id {raw_line!r}; expected CVE-YYYY-NNNN")
        cves.append(raw_line)
    if not cves:
        raise ValueError(f"CVE file is empty: {path}")
    return validate_cve_ids(cves, str(path))


def resolve_git_repo(path: Path) -> Path:
    repo = path.expanduser().resolve()
    if not repo.exists():
        raise ValueError(f"repo path does not exist: {repo}")
    if not repo.is_dir():
        raise ValueError(f"repo path is not a directory: {repo}")
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode or proc.stdout.strip() != "true":
        detail = proc.stderr.strip() or proc.stdout.strip()
        suffix = f": {detail}" if detail else ""
        raise ValueError(f"repo path is not a git worktree: {repo}{suffix}")
    top = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if top.returncode == 0 and top.stdout.strip():
        return Path(top.stdout.strip()).resolve()
    return repo


def run_stage(name: str, func, config: BuildConfig, db: ProjectDB, log, *, cves: list[str] | None = None) -> None:
    context = {"stage_name": name}
    if cves is not None:
        context["cves"] = cves
    log.trace("stage start", **context)
    func(config, db)
    log.trace("stage done", **context)


def run_scoped_resume(
    config: BuildConfig,
    db: ProjectDB,
    log,
    *,
    metadata_prepared: bool = False,
) -> None:
    variant_only_cves, bootstrap_cves = db.classify_requested_cves(config.cves, config)
    log.trace(
        "resume CVE classification",
        variant_only_cves=variant_only_cves,
        bootstrap_cves=bootstrap_cves,
        compiler=config.compiler,
        opt=config.opt,
    )
    if bootstrap_cves:
        bootstrap_config = config.with_cves(bootstrap_cves)
        bootstrap_stages = (
            ("git_update", update_git_repo),
            ("cve_metadata", update_cve_metadata),
            ("cve2diff", run_cve2diff),
            ("source_analysis", run_source_analysis),
            ("reference_build", run_reference_build),
            ("releases", update_releases),
            ("testset", select_default_entries),
        )
        for stage_name, func in bootstrap_stages:
            if metadata_prepared and stage_name in {"git_update", "cve_metadata"}:
                log.trace("stage skipped", stage_name=stage_name, reason="latest selection already refreshed")
                continue
            if stage_name not in {"git_update", "releases"} and db.stage_satisfied(stage_name, bootstrap_config):
                log.trace("stage skipped", stage_name=stage_name, reason="bootstrap content satisfied")
                continue
            run_stage(stage_name, func, bootstrap_config, db, log, cves=bootstrap_cves)

    target_cves = [*variant_only_cves, *bootstrap_cves]
    target_config = config.with_cves(target_cves)
    if target_cves and not db.stage_satisfied("target_build", target_config):
        run_stage("target_build", run_target_build, target_config, db, log, cves=target_cves)

    review_cves = sorted(
        set(bootstrap_cves) | {candidate["cve_id"] for candidate in db.pending_not_affected_candidates(target_config)}
    )
    if review_cves:
        run_stage(
            "not_affected_review",
            run_not_affected_review,
            config.with_cves(review_cves),
            db,
            log,
            cves=review_cves,
        )

    if target_cves and not db.stage_satisfied("debug_split", target_config):
        run_stage("debug_split", run_debug_split, target_config, db, log, cves=target_cves)

    export_variant_testset_and_groundtruth(config, db)
    if bootstrap_cves:
        export_outputs(config.all_cves_config(), db)
    if config.metadata_mode != "skip" and target_cves and not db.stage_satisfied("RCA", target_config):
        run_stage("RCA", run_rca_metadata, target_config, db, log, cves=target_cves)


def latest_resume_needs_work(config: BuildConfig, db: ProjectDB, cve_id: str) -> bool:
    if not db.cve_base_ready(cve_id, config):
        return True
    scoped_config = config.with_cves([cve_id])
    if not db.stage_satisfied("target_build", scoped_config):
        return True
    if not db.stage_satisfied("debug_split", scoped_config):
        return True
    return config.metadata_mode != "skip" and not db.stage_satisfied("RCA", scoped_config)


def run_latest_resume(config: BuildConfig, db: ProjectDB, log) -> None:
    """Refresh a latest-N selection window, then bootstrap only new or incomplete CVEs."""
    previously_selected = {row["cve_id"] for row in db.selected_cves()}
    run_stage("git_update", update_git_repo, config, db, log)
    selected_window = update_cve_metadata(config, db)
    update_cves = [
        cve_id
        for cve_id in selected_window
        if cve_id not in previously_selected or latest_resume_needs_work(config, db, cve_id)
    ]
    log.trace(
        "latest CVE selection refreshed",
        latest=config.latest,
        selected_window=len(selected_window),
        existing_selected=len(previously_selected),
        update_cves=update_cves,
    )
    if not update_cves:
        log.trace("latest CVE selection has no new or incomplete CVEs")
        return
    run_scoped_resume(config.with_cves(update_cves), db, log, metadata_prepared=True)


def run_standard_pipeline(config: BuildConfig, db: ProjectDB, log) -> None:
    stages = (
        ("git_update", update_git_repo),
        ("cve_metadata", update_cve_metadata),
        ("cve2diff", run_cve2diff),
        ("source_analysis", run_source_analysis),
        ("reference_build", run_reference_build),
        ("releases", update_releases),
        ("testset", select_default_entries),
        ("target_build", run_target_build),
        ("not_affected_review", run_not_affected_review),
        ("debug_split", run_debug_split),
        ("variant_export", export_variant_testset_and_groundtruth),
        ("export", export_outputs),
        ("RCA", run_rca_metadata),
    )
    ran_any_stage = False
    for stage_name, func in stages:
        force_run = stage_name in {"variant_export", "export"} and ran_any_stage
        if config.resume and not force_run and db.stage_satisfied(stage_name, config):
            log.trace("stage skipped", stage_name=stage_name, reason="resume satisfied")
            continue
        run_stage(stage_name, func, config, db, log)
        ran_any_stage = True


def run_locked_manifest_pipeline(config: BuildConfig, db: ProjectDB, log) -> None:
    """Build the exact manifest testcase set without rerunning CVE/source discovery."""
    run_stage("releases", update_releases, config, db, log)
    apply_locked_manifest(config, db)
    run_stage("reference_build", run_reference_build, config, db, log)
    missing_references = db.selected_fixes_missing_reference(config)
    if missing_references:
        raise RuntimeError(f"locked manifest reference build is incomplete: {missing_references}")
    run_stage("target_build", run_target_build, config, db, log)
    apply_locked_manifest_reviews(config, db)
    run_stage("debug_split", run_debug_split, config, db, log)
    run_stage("variant_export", export_variant_testset_and_groundtruth, config, db, log)
    run_stage("export", export_outputs, config, db, log)
    align_locked_manifest_exports(config)
    result = validate_locked_manifest_exports(config)
    db.record_stage("locked_manifest_validation", "ok", result)
    log.trace("locked manifest dataset validated", **result)


def handle_build(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    db_path = (args.db.expanduser().resolve() if args.db else output / f"{args.project}.sqlite")
    base_config = load_base_config()
    if args.testset_count < 1:
        raise SystemExit("error: --testset-count must be >= 1")
    testset_count = args.testset_count
    testset_strategy = normalize_testset_strategy(args.testset_strategy)
    try:
        if args.testset_manifest:
            cves = validate_cve_ids(manifest_cves(args.testset_manifest, args.project), str(args.testset_manifest))
        else:
            cves = read_cve_file(args.cve_file) if args.cve_file else validate_cve_ids(args.cve or [], "--cve")
        repo = resolve_git_repo(args.repo)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}") from exc
    config = BuildConfig(
        project=args.project,
        repo=repo,
        output=output,
        db_path=db_path,
        vendor_product=infer_vendor_product(args.project, args.vendor_product, base_config),
        latest=args.latest or 0,
        cves=cves,
        compiler=args.compiler,
        opt=args.opt,
        codex_model=args.codex_model,
        codex_sandbox=args.codex_sandbox,
        batch_size=args.batch_size,
        github_token=args.github_token,
        nvd_api_key=args.nvd_api_key,
        metadata_mode=args.metadata_mode,
        resume=args.resume,
        cleanup_worktrees=args.cleanup_worktrees,
        cleanup_build_logs=args.cleanup_build_logs,
        testset_count=testset_count,
        testset_strategy=testset_strategy,
        architecture=getattr(args, "arch", "x86_64"),
        testset_manifest=args.testset_manifest.expanduser().resolve() if args.testset_manifest else None,
    )
    try:
        validate_toolchain(config.architecture, config.compiler)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}") from exc
    db = ProjectDB(config.db_path)
    log = get_logger(output, "pipeline")
    try:
        write_config(db, config)
        if config.testset_manifest is not None:
            run_locked_manifest_pipeline(config, db, log)
        elif config.resume and config.cves:
            run_scoped_resume(config, db, log)
        elif config.resume and config.latest:
            run_latest_resume(config, db, log)
        else:
            run_standard_pipeline(config, db, log)
    finally:
        db.close()
    return 0


def handle_cleanup_worktrees(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    db_path = (args.db.expanduser().resolve() if args.db else output / f"{args.project}.sqlite")
    config = BuildConfig(
        project=args.project,
        repo=args.repo.expanduser().resolve(),
        output=output,
        db_path=db_path,
        vendor_product=f"{args.project}:{args.project}",
        latest=0,
        cves=[],
        compiler="",
        opt="",
        codex_model="",
        codex_sandbox="danger-full-access",
        batch_size=0,
        github_token="",
        nvd_api_key="",
        metadata_mode="skip",
        resume=False,
        cleanup_worktrees="none" if args.dry_run else "all",
        cleanup_build_logs="none",
        testset_count=3,
        testset_strategy="chronical",
        architecture="x86_64",
    )
    log = get_logger(output, "cleanup_worktrees")
    worktrees = list_project_worktrees(output, args.project)
    if args.dry_run:
        for worktree in sorted(worktrees):
            print(worktree)
        print(f"worktrees={len(worktrees)}")
        return 0
    removed = remove_worktrees(config, worktrees, log, success=False, reason="manual cleanup command")
    log.trace("manual worktree cleanup complete", found=len(worktrees), removed=removed)
    print(f"removed={removed} found={len(worktrees)}")
    return 0


def handle_cleanup_build_logs(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    logs = list_build_logs(output, args.stage)
    if args.dry_run:
        for path in logs:
            print(path)
        print(f"logs={len(logs)}")
        return 0
    log = get_logger(output, "cleanup_build_logs")
    removed = remove_existing_build_logs(output, log, args.stage)
    print(f"removed={removed} found={len(logs)}")
    return 0


def handle_select_rq_testset(args: argparse.Namespace) -> int:
    from testset.rq_selection import select_rq2_rq3_testset

    try:
        repo = resolve_git_repo(args.repo)
        result = select_rq2_rq3_testset(
            project=args.project,
            repo=repo,
            output=args.output,
            count=args.count,
            variant=args.variant,
        )
    except ValueError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)
