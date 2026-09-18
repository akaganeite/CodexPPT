from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from binarybuild.not_affected_review import POLICY as AFFECTEDNESS_POLICY
from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger
from utils.io import write_json


LABELS = ("vuln", "patch", "not_affected")


def load_project_manifest(path: Path, project: str) -> dict[str, dict[str, list[str]]]:
    manifest_path = path.expanduser().resolve()
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"failed to read testset manifest {manifest_path}: {exc}") from exc
    project_data = data.get(project) if isinstance(data, dict) else None
    if not isinstance(project_data, dict) or not project_data:
        raise ValueError(f"testset manifest has no non-empty project entry {project!r}")

    normalized: dict[str, dict[str, list[str]]] = {}
    for cve_id, item in project_data.items():
        if not isinstance(item, dict):
            raise ValueError(f"testset manifest {project}/{cve_id} must be an object")
        labels: dict[str, list[str]] = {}
        seen: set[str] = set()
        for label in LABELS:
            binaries = item.get(label, [])
            if not isinstance(binaries, list) or not all(isinstance(name, str) and name for name in binaries):
                raise ValueError(f"testset manifest {project}/{cve_id}/{label} must be a string list")
            duplicate = seen.intersection(binaries)
            if duplicate:
                raise ValueError(f"testset manifest labels overlap for {cve_id}: {sorted(duplicate)}")
            seen.update(binaries)
            labels[label] = list(binaries)
        if not seen:
            raise ValueError(f"testset manifest has no binaries for {project}/{cve_id}")
        normalized[str(cve_id)] = labels
    return normalized


def manifest_cves(path: Path, project: str) -> list[str]:
    return list(load_project_manifest(path, project))


def parse_logical_binary(project: str, name: str) -> tuple[str, str]:
    prefix = f"{project}-"
    if not name.startswith(prefix):
        raise ValueError(f"manifest binary {name!r} does not start with {prefix!r}")
    body = name[len(prefix) :]
    if "-" not in body:
        raise ValueError(f"manifest binary {name!r} has no binary-name suffix")
    version, binary_name = body.rsplit("-", 1)
    if not version or not binary_name:
        raise ValueError(f"manifest binary {name!r} has an invalid version/binary split")
    return version, binary_name


def logical_binary_name(project: str, version: str, binary_name: str) -> str:
    return f"{project}-{version}-{binary_name}"


def _existing_entry(db: ProjectDB, cve_id: str, version: str, binary_name: str):
    return db.conn.execute(
        """
        SELECT * FROM testset_entries
        WHERE cve_id=? AND version=? AND binary_name=?
        ORDER BY status='selected' DESC,updated_at DESC,id DESC
        LIMIT 1
        """,
        (cve_id, version, binary_name),
    ).fetchone()


def _release_for_version(db: ProjectDB, version: str):
    rows = db.conn.execute(
        """
        SELECT * FROM releases
        WHERE version=? OR norm_tag=?
        ORDER BY CASE WHEN version=? THEN 0 ELSE 1 END,date DESC,tag
        """,
        (version, version, version),
    ).fetchall()
    if not rows:
        return None
    exact_tag = [row for row in rows if row["tag"] == version]
    return exact_tag[0] if exact_tag else rows[0]


def _entry_for_manifest_case(
    config: BuildConfig,
    db: ProjectDB,
    cve_id: str,
    final_label: str,
    name: str,
) -> dict[str, str]:
    version, binary_name = parse_logical_binary(config.project, name)
    existing = _existing_entry(db, cve_id, version, binary_name)
    release = existing or _release_for_version(db, version)
    if release is None:
        raise ValueError(f"manifest testcase has no release tag: {cve_id} {name}")
    internal_label = final_label
    if final_label == "not_affected":
        internal_label = existing["label"] if existing and existing["label"] in {"vuln", "patch"} else "vuln"
    return {
        "label": internal_label,
        "version": version,
        "tag": release["tag"],
        "binary_name": binary_name,
        "reason": f"locked manifest final_label={final_label}",
        "status": "selected",
    }


def apply_locked_manifest(config: BuildConfig, db: ProjectDB) -> dict[str, Any]:
    if config.testset_manifest is None:
        raise ValueError("locked manifest stage requires config.testset_manifest")
    manifest = load_project_manifest(config.testset_manifest, config.project)
    cve_ids = list(manifest)
    placeholders = ",".join("?" for _ in cve_ids)
    existing_cves = {
        row["cve_id"]
        for row in db.conn.execute(f"SELECT cve_id FROM cves WHERE cve_id IN ({placeholders})", cve_ids)
    }
    missing_cves = sorted(set(cve_ids) - existing_cves)
    if missing_cves:
        raise ValueError(f"manifest CVEs are missing from the project database: {missing_cves}")

    # A locked dataset has exactly the manifest CVEs. Deleting unrelated testset
    # rows also removes stale mappings/reviews through foreign-key cascades.
    db.conn.execute("UPDATE cves SET selected=0")
    db.conn.execute(f"UPDATE cves SET selected=1 WHERE cve_id IN ({placeholders})", cve_ids)
    db.conn.execute(f"DELETE FROM testset_entries WHERE cve_id NOT IN ({placeholders})", cve_ids)
    db.conn.commit()

    testcase_count = 0
    for cve_id, labels in manifest.items():
        entries = []
        for final_label in LABELS:
            for name in labels[final_label]:
                entries.append(_entry_for_manifest_case(config, db, cve_id, final_label, name))
                testcase_count += 1
        db.replace_testset_entries(cve_id, entries)

    manifest_bytes = config.testset_manifest.expanduser().resolve().read_bytes()
    detail = {
        "strategy": "locked-manifest",
        "manifest": str(config.testset_manifest.expanduser().resolve()),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "project": config.project,
        "cves": len(manifest),
        "testcases": testcase_count,
    }
    db.set_project_value("locked_testset_manifest", detail)
    db.record_stage("testset", "ok", detail)
    get_logger(config.output, "testset_manifest").trace("locked testset manifest applied", **detail)
    return detail


def apply_locked_manifest_reviews(config: BuildConfig, db: ProjectDB) -> dict[str, Any]:
    if config.testset_manifest is None:
        raise ValueError("locked manifest review stage requires config.testset_manifest")
    manifest = load_project_manifest(config.testset_manifest, config.project)
    final_labels = {
        (cve_id, name): label
        for cve_id, labels in manifest.items()
        for label in LABELS
        for name in labels[label]
    }
    missing: list[str] = []
    counts = {label: 0 for label in LABELS}
    for row in db.testset_entries(config):
        name = logical_binary_name(config.project, row["version"], row["binary_name"])
        final_label = final_labels.get((row["cve_id"], name))
        if final_label is None:
            raise ValueError(f"database testcase is not present in locked manifest: {row['cve_id']} {name}")
        mapping = db.target_mapping_for_testset(row, config)
        if mapping is None:
            missing.append(f"{row['cve_id']}:{name}")
            continue
        status = "not_affected" if final_label == "not_affected" else "affected"
        report = {
            "policy": AFFECTEDNESS_POLICY,
            "review_protocol": "authoritative-locked-manifest-v1",
            "manifest": str(config.testset_manifest.expanduser().resolve()),
            "final_label": final_label,
        }
        db.conn.execute(
            "DELETE FROM affectedness_reviews WHERE testset_entry_id=? AND policy=? AND architecture=?",
            (row["id"], AFFECTEDNESS_POLICY, config.architecture),
        )
        db.conn.execute(
            """
            INSERT INTO affectedness_reviews(
              testset_entry_id,reviewed_artifact_id,policy,architecture,status,confidence,reason,
              evidence_json,suggested_action,missing_functions_json,report_json,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
            """,
            (
                row["id"],
                mapping["artifact_id"],
                AFFECTEDNESS_POLICY,
                config.architecture,
                status,
                1.0,
                f"authoritative locked manifest label: {final_label}",
                json.dumps([{"source": "locked_manifest", "label": final_label}], ensure_ascii=False),
                "preserve locked manifest label",
                "[]",
                json.dumps(report, ensure_ascii=False),
            ),
        )
        counts[final_label] += 1
    db.conn.commit()
    if missing:
        raise ValueError(f"locked manifest reviews have missing target mappings: {missing}")
    detail = {
        "policy": AFFECTEDNESS_POLICY,
        "review_protocol": "authoritative-locked-manifest-v1",
        "architecture": config.architecture,
        "counts": counts,
    }
    db.record_stage("not_affected_review", "ok", detail)
    get_logger(config.output, "testset_manifest").trace("locked manifest labels recorded", **detail)
    return detail


def align_locked_manifest_exports(config: BuildConfig) -> None:
    """Preserve the manifest's CVE, label, and testcase ordering in final exports."""
    if config.testset_manifest is None:
        raise ValueError("locked manifest export alignment requires config.testset_manifest")
    manifest = load_project_manifest(config.testset_manifest, config.project)
    suffix = config.build_variant
    export_specs = [
        (config.exports_dir / f"testset.{suffix}.json", "testset"),
        (config.exports_dir / f"groundtruth.{suffix}.json", "groundtruth"),
        (config.exports_dir / f"groundtruth_with_not_affected.{suffix}.json", "groundtruth"),
        (config.exports_dir / f"not_affected.{suffix}.json", "not_affected"),
    ]
    if config.architecture == "x86_64":
        export_specs.extend(
            [
                (config.exports_dir / "testset.json", "testset"),
                (config.exports_dir / "groundtruth.json", "groundtruth"),
                (config.exports_dir / "groundtruth_with_not_affected.json", "groundtruth"),
                (config.exports_dir / "not_affected.json", "not_affected"),
            ]
        )

    metadata_path = config.exports_dir / (
        f"{config.project}_metadata.json"
        if config.architecture == "x86_64"
        else f"{config.project}_metadata.{config.architecture}.json"
    )
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        write_json(metadata_path, {cve_id: metadata[cve_id] for cve_id in manifest if cve_id in metadata})

    reference_path = config.exports_dir / (
        f"{config.project}_reference.json"
        if config.architecture == "x86_64"
        else f"{config.project}_reference.{config.architecture}.json"
    )
    if reference_path.exists():
        references = json.loads(reference_path.read_text(encoding="utf-8"))
        by_cve = {item["CVE"]: item for item in references}
        write_json(reference_path, [by_cve[cve_id] for cve_id in manifest if cve_id in by_cve])

    for path, kind in export_specs:
        if not path.exists():
            continue
        items = json.loads(path.read_text(encoding="utf-8"))
        by_cve = {item["CVE"]: item for item in items}
        ordered: list[dict[str, Any]] = []
        for cve_id, labels in manifest.items():
            if kind == "not_affected" and not labels["not_affected"]:
                continue
            source = by_cve.get(cve_id, {})
            item = {"CVE": cve_id, "functions": list(source.get("functions", []))}
            if kind in {"testset", "not_affected"}:
                item["binaries"] = (
                    list(labels["not_affected"])
                    if kind == "not_affected"
                    else [name for label in LABELS for name in labels[label]]
                )
            else:
                for label in LABELS:
                    item[label] = list(labels[label])
            ordered.append(item)
        write_json(path, ordered)


def validate_locked_manifest_exports(config: BuildConfig) -> dict[str, Any]:
    if config.testset_manifest is None:
        raise ValueError("locked manifest export validation requires config.testset_manifest")
    manifest = load_project_manifest(config.testset_manifest, config.project)
    suffix = config.build_variant
    testset_path = config.exports_dir / f"testset.{suffix}.json"
    groundtruth_path = config.exports_dir / f"groundtruth.{suffix}.json"
    testset_items = json.loads(testset_path.read_text(encoding="utf-8"))
    groundtruth_items = json.loads(groundtruth_path.read_text(encoding="utf-8"))
    expected_cves = list(manifest)
    if [item["CVE"] for item in testset_items] != expected_cves:
        raise RuntimeError("locked manifest testset CVE sequence mismatch")
    if [item["CVE"] for item in groundtruth_items] != expected_cves:
        raise RuntimeError("locked manifest groundtruth CVE sequence mismatch")
    testset = {item["CVE"]: item for item in testset_items}
    groundtruth = {item["CVE"]: item for item in groundtruth_items}
    if set(testset) != set(manifest) or set(groundtruth) != set(manifest):
        raise RuntimeError("locked manifest export CVE set mismatch")
    for cve_id, labels in manifest.items():
        expected = [name for label in LABELS for name in labels[label]]
        if testset[cve_id].get("binaries", []) != expected:
            raise RuntimeError(f"locked manifest testset mismatch for {cve_id}")
        for label in LABELS:
            if groundtruth[cve_id].get(label, []) != labels[label]:
                raise RuntimeError(f"locked manifest groundtruth mismatch for {cve_id}/{label}")
    return {
        "project": config.project,
        "cves": len(manifest),
        "testcases": sum(len(labels[label]) for labels in manifest.values() for label in LABELS),
        "testset": str(testset_path),
        "groundtruth": str(groundtruth_path),
    }
