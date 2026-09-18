from __future__ import annotations

import json
from pathlib import Path

from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger
from binarybuild.not_affected_review import LEGACY_POLICIES, POLICY as AFFECTEDNESS_POLICY
from binarybuild.target_mapping_reconcile import reconcile_existing_variant_mappings
from testset.testset_stage import version_token_key
from utils.io import write_json


def strip_variant_suffix(config: BuildConfig, name: str) -> str:
    suffix = f"-{config.build_variant}"
    return name[: -len(suffix)] if name.endswith(suffix) else name


def export_file_name(stem: str, suffix: str = "") -> str:
    return f"{stem}.{suffix}.json" if suffix else f"{stem}.json"


def testset_export_name(config: BuildConfig, db: ProjectDB, row) -> str:
    mapping = db.target_mapping_for_testset(row, config)
    name = Path(mapping["path"]).name if mapping and mapping["path"] else config.target_binary_name(row["version"], row["binary_name"])
    return strip_variant_suffix(config, name)


def not_affected_export_name(config: BuildConfig, db: ProjectDB, item: dict) -> str:
    row = db.conn.execute(
        """
        SELECT * FROM testset_entries
        WHERE cve_id=? AND label=? AND tag=? AND binary_name=? AND status='selected'
        LIMIT 1
        """,
        (item["CVE"], item.get("label", ""), item.get("tag", ""), item.get("binary", "")),
    ).fetchone()
    if row:
        return testset_export_name(config, db, row)
    target_path = item.get("target_path") or ""
    if target_path:
        return strip_variant_suffix(config, Path(target_path).name)
    return item.get("binary", "")


def aggregate_testset_rows(config: BuildConfig, db: ProjectDB, rows, name_for_row) -> tuple[dict[str, dict], dict[str, dict]]:
    groundtruth: dict[str, dict] = {}
    testset: dict[str, dict] = {}
    for row in rows:
        cve_id = row["cve_id"]
        functions = db.functions_for_cve(cve_id)
        gt_item = groundtruth.setdefault(cve_id, {"CVE": cve_id, "functions": functions, "vuln": [], "patch": []})
        ts_item = testset.setdefault(cve_id, {"CVE": cve_id, "functions": functions, "binaries": []})
        if "status" in row.keys() and row["status"] != "selected":
            continue
        name = name_for_row(row)
        if row["label"] in ("vuln", "patch") and name not in gt_item[row["label"]]:
            gt_item[row["label"]].append(name)
        if name not in ts_item["binaries"]:
            ts_item["binaries"].append(name)
    for item in testset.values():
        item["binaries"].sort()
    for item in groundtruth.values():
        item["vuln"].sort()
        item["patch"].sort()
    return testset, groundtruth


def export_testset_and_groundtruth(config: BuildConfig, db: ProjectDB) -> tuple[dict[str, dict], dict[str, dict]]:
    testset, groundtruth = aggregate_testset_rows(
        config, db, db.testset_entries(config), lambda row: testset_export_name(config, db, row)
    )
    write_json(config.exports_dir / "testset.json", list(testset.values()))
    return testset, groundtruth


def export_variant_testset_and_groundtruth(config: BuildConfig, db: ProjectDB) -> tuple[int, int]:
    log = get_logger(config.output, "variant_export")
    reconciled = reconcile_existing_variant_mappings(config, db, full_scope=True, log=log)
    rows = db.variant_export_rows(config)
    testset, groundtruth = aggregate_testset_rows(
        config,
        db,
        rows,
        lambda row: strip_variant_suffix(config, Path(row["path"]).name),
    )
    suffix = config.build_variant
    review_items = build_review_items(db, rows)
    merged_gt, not_affected_view = merge_affectedness_views(config, db, groundtruth, review_items)
    pick = build_testset_pick(config, db, rows, lambda row: strip_variant_suffix(config, Path(row["path"]).name))
    validate_tri_state_export(testset, merged_gt)
    validate_testset_pick(pick, merged_gt)

    write_json(config.exports_dir / export_file_name("testset", suffix), list(testset.values()))
    write_json(config.exports_dir / export_file_name("testset.pick", suffix), list(pick.values()))
    write_json(config.exports_dir / export_file_name("groundtruth", suffix), list(merged_gt.values()))
    write_affectedness_views(config, merged_gt, not_affected_view, suffix)
    write_json(config.exports_dir / export_file_name("not_affected_candidates", suffix), review_items)
    write_json(config.exports_dir / export_file_name("affectedness_audit_summary", suffix), review_status_counts(review_items))
    db.record_stage(
        "variant_export",
        "ok",
        {
            "testset": len(testset),
            "testset_pick": len(pick),
            "groundtruth": len(groundtruth),
            "not_affected": len(not_affected_view),
            "reconciled_existing_artifacts": reconciled,
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
        },
    )
    return len(testset), len(groundtruth)


def build_review_items(db: ProjectDB, candidates: list[dict]) -> list[dict]:
    items: list[dict] = []
    for candidate in candidates:
        review = db.not_affected_review_for_candidate(
            candidate,
            policy=AFFECTEDNESS_POLICY,
            fallback_policies=LEGACY_POLICIES,
        )
        review_item = None
        if review:
            review_item = {
                "status": review["status"],
                "confidence": review["confidence"],
                "reason": review["reason"],
                "evidence": json.loads(review["evidence_json"] or "[]"),
                "suggested_action": review["suggested_action"],
                "compiler": review["compiler"],
                "opt": review["opt"],
                "build_profile": review["build_profile"],
                "policy": review["policy"],
            }
        items.append(
            {
                "CVE": candidate["cve_id"],
                "label": candidate.get("label", ""),
                "tag": candidate["tag"],
                "binary": candidate["binary_name"],
                "target_path": candidate.get("target_path") or candidate.get("path", ""),
                "compiler": candidate.get("compiler", ""),
                "opt": candidate.get("opt", ""),
                "build_profile": candidate.get("build_profile", ""),
                "candidate_type": candidate.get("candidate_type", "affectedness_audit"),
                "missing_functions": candidate.get("missing_functions", []),
                "reason": candidate.get("reason", "selected target affectedness audit"),
                "review": review_item,
            }
        )
    return items


def merge_affectedness_views(
    config: BuildConfig, db: ProjectDB, groundtruth: dict[str, dict], review_items: list[dict]
) -> tuple[dict[str, dict], dict[str, dict]]:
    not_affected_view: dict[str, dict] = {}
    merged_gt = {
        cve_id: {
            "CVE": item["CVE"],
            "functions": list(item.get("functions", [])),
            "vuln": list(item.get("vuln", [])),
            "patch": list(item.get("patch", [])),
            "not_affected": [],
        }
        for cve_id, item in groundtruth.items()
    }
    for item in review_items:
        review = item.get("review") or {}
        status = review.get("status") or ""
        if status not in {"not_affected", "backport_fix", "patch_evolution", "missing_fix"}:
            continue
        cve_id = item["CVE"]
        functions = db.functions_for_cve(cve_id)
        name = not_affected_export_name(config, db, item)
        gt_item = merged_gt.setdefault(cve_id, {"CVE": cve_id, "functions": functions, "vuln": [], "patch": [], "not_affected": []})
        if name:
            gt_item["vuln"] = [binary for binary in gt_item["vuln"] if binary != name]
            gt_item["patch"] = [binary for binary in gt_item["patch"] if binary != name]
        if status in {"backport_fix", "patch_evolution"}:
            if name and name not in gt_item["patch"]:
                gt_item["patch"].append(name)
        elif status == "missing_fix":
            if name and name not in gt_item["vuln"]:
                gt_item["vuln"].append(name)
        elif status == "not_affected":
            na_item = not_affected_view.setdefault(cve_id, {"CVE": cve_id, "functions": functions, "binaries": []})
            if name and name not in na_item["binaries"]:
                na_item["binaries"].append(name)
            if name and name not in gt_item["not_affected"]:
                gt_item["not_affected"].append(name)

    for item in not_affected_view.values():
        item["binaries"].sort()
    for item in merged_gt.values():
        item["vuln"].sort()
        item["patch"].sort()
        item["not_affected"].sort()

    return merged_gt, not_affected_view


def write_affectedness_views(
    config: BuildConfig, groundtruth: dict[str, dict], not_affected: dict[str, dict], suffix: str = ""
) -> None:
    write_json(config.exports_dir / export_file_name("not_affected", suffix), list(not_affected.values()))
    write_json(config.exports_dir / export_file_name("groundtruth_with_not_affected", suffix), list(groundtruth.values()))


def build_testset_pick(config: BuildConfig, db: ProjectDB, rows, name_for_row) -> dict[str, dict]:
    grouped: dict[str, dict[str, list[tuple[tuple, str]]]] = {}
    functions: dict[str, list[str]] = {}
    for row in rows:
        if "status" in row.keys() and row["status"] != "selected":
            continue
        if row["label"] not in {"vuln", "patch"}:
            continue
        cve_id = row["cve_id"]
        functions.setdefault(cve_id, db.functions_for_cve(cve_id))
        name = name_for_row(row)
        key = (version_token_key(str(row["version"])), str(row["tag"]), name)
        grouped.setdefault(cve_id, {"vuln": [], "patch": []})[row["label"]].append((key, name))

    pick: dict[str, dict] = {}
    for cve_id, by_label in grouped.items():
        binaries: list[str] = []
        if by_label["vuln"]:
            binaries.append(min(by_label["vuln"], key=lambda item: item[0])[1])
        if by_label["patch"]:
            binaries.append(max(by_label["patch"], key=lambda item: item[0])[1])
        pick[cve_id] = {"CVE": cve_id, "functions": functions[cve_id], "binaries": list(dict.fromkeys(binaries))}
    return pick


def validate_tri_state_export(testset: dict[str, dict], groundtruth: dict[str, dict]) -> None:
    if set(testset) != set(groundtruth):
        raise RuntimeError("testset and tri-state groundtruth CVE sets differ")
    for cve_id, testset_item in testset.items():
        groundtruth_item = groundtruth[cve_id]
        labels = [
            *groundtruth_item.get("vuln", []),
            *groundtruth_item.get("patch", []),
            *groundtruth_item.get("not_affected", []),
        ]
        if len(labels) != len(set(labels)):
            raise RuntimeError(f"tri-state groundtruth has duplicate labels for {cve_id}")
        if set(labels) != set(testset_item.get("binaries", [])):
            raise RuntimeError(f"tri-state groundtruth does not cover the testset for {cve_id}")


def validate_testset_pick(pick: dict[str, dict], groundtruth: dict[str, dict]) -> None:
    for cve_id, item in pick.items():
        if cve_id not in groundtruth:
            raise RuntimeError(f"testset pick contains unknown CVE {cve_id}")
        labels = set(groundtruth[cve_id].get("vuln", []))
        labels.update(groundtruth[cve_id].get("patch", []))
        labels.update(groundtruth[cve_id].get("not_affected", []))
        missing = set(item.get("binaries", [])) - labels
        if missing:
            raise RuntimeError(f"testset pick has unlabeled binaries for {cve_id}: {sorted(missing)}")


def review_status_counts(items: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        review = item.get("review") or {}
        status = review.get("status") or "pending"
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def export_outputs(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "export")
    config.exports_dir.mkdir(parents=True, exist_ok=True)

    metadata = {}
    for row in db.selected_fixes(config):
        cve_id = row["cve_id"]
        functions = db.functions_for_cve(cve_id)
        details = db.function_details_for_cve(cve_id)
        by_function = {}
        for detail in details:
            by_function.setdefault(
                detail["function"],
                {
                    "file": detail["file_path"] or "",
                    "change_type": detail["change_type"] or "",
                },
            )
        metadata[cve_id] = {
            "functions": functions,
            "summary": row["summary"],
            "cwe": json.loads(row["cwe_json"] or "[]"),
            "diff_related": [{"file": row["diff_path"]}],
            "function_code": {
                "commit": row["commit_hash"],
                "by_function": by_function or {fn: {"file": ""} for fn in functions},
            },
        }
    if config.architecture == "x86_64":
        write_json(config.exports_dir / f"{config.project}_metadata.json", metadata)
    else:
        write_json(config.exports_dir / f"{config.project}_metadata.{config.architecture}.json", metadata)

    refs = []
    for row in db.references(config):
        refs.append(
            {
                "CVE": row["cve_id"],
                "vuln": row["vuln_path"].split("/")[-1],
                "patch": row["patch_path"].split("/")[-1],
                "functions": json.loads(row["functions_json"] or "[]"),
                "compiler": row["compiler"],
                "opt": row["opt"],
                "build_profile": row["build_profile"],
            }
        )
    reference_name = (
        f"{config.project}_reference.json"
        if config.architecture == "x86_64"
        else f"{config.project}_reference.{config.architecture}.json"
    )
    write_json(config.exports_dir / reference_name, refs)

    if config.architecture != "x86_64":
        db.record_stage(
            "export",
            "ok",
            {
                "metadata": len(metadata),
                "reference": len(refs),
                "canonical_exports": False,
                "architecture": config.architecture,
                "compiler": config.compiler,
                "opt": config.opt,
            },
        )
        log.trace("architecture-scoped exports written", output=str(config.exports_dir), architecture=config.architecture)
        return

    testset, groundtruth = export_testset_and_groundtruth(config, db)

    review_items = build_review_items(db, db.global_not_affected_candidates(config))
    merged_gt, not_affected_view = merge_affectedness_views(config, db, groundtruth, review_items)
    pick = build_testset_pick(config, db, db.testset_entries(config), lambda row: testset_export_name(config, db, row))
    validate_tri_state_export(testset, merged_gt)
    validate_testset_pick(pick, merged_gt)
    write_json(config.exports_dir / "testset.pick.json", list(pick.values()))
    write_json(config.exports_dir / "groundtruth.json", list(merged_gt.values()))
    write_json(config.exports_dir / "not_affected_candidates.json", review_items)
    write_json(config.exports_dir / "affectedness_audit_summary.json", review_status_counts(review_items))
    write_affectedness_views(config, merged_gt, not_affected_view)
    db.record_stage(
        "export",
        "ok",
        {
            "metadata": len(metadata),
            "reference": len(refs),
            "testset": len(testset),
            "groundtruth": len(groundtruth),
            "testset_pick": len(pick),
            "not_affected": len(review_items),
            "not_affected_merged": len(not_affected_view),
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
        },
    )
    log.trace("exports written", output=str(config.exports_dir))
