from __future__ import annotations

import json
from typing import Any, Iterable

from builder.architecture import matches_elf_architecture
from builder.config import REFERENCE_BUILD_PROFILE, REFERENCE_COMPILER, REFERENCE_OPT
from binarybuild.reference_validation import partition_reference_functions, validate_reference_pair


class ResumeStateMixin:
    def _reference_is_usable(self, cve_id: str, reference: Any, config: Any | None = None) -> bool:
        if not reference:
            return False
        vuln = self.resolve_path(reference["vuln_path"])
        patch = self.resolve_path(reference["patch_path"])
        architecture = self.architecture_filter(config)
        if (
            not vuln.exists()
            or not patch.exists()
            or not matches_elf_architecture(vuln, architecture)
            or not matches_elf_architecture(patch, architecture)
        ):
            return False
        try:
            functions = json.loads(reference["functions_json"] or "[]")
        except (IndexError, KeyError, json.JSONDecodeError):
            functions = []
        if not functions:
            return True
        details = self.conn.execute(
            "SELECT function,change_type FROM source_functions WHERE cve_id=? AND active=1",
            (cve_id,),
        ).fetchall()
        vuln_functions, patch_functions = partition_reference_functions(functions, details)
        toolchain = getattr(config, "toolchain", None)
        nm = getattr(toolchain, "nm", "") or (
            "aarch64-linux-gnu-nm" if architecture == "aarch64" else "nm"
        )
        return validate_reference_pair(
            vuln,
            patch,
            vuln_functions=vuln_functions,
            patch_functions=patch_functions,
            architecture=architecture,
            nm=nm,
        ).valid

    def record_stage(self, stage: str, status: str, detail: Any = None) -> None:
        self.conn.execute(
            "INSERT INTO stage_runs(stage, status, detail_json) VALUES (?, ?, ?)",
            (stage, status, json.dumps(detail or {}, ensure_ascii=False, default=str)),
        )
        self.conn.execute(
            """
            DELETE FROM stage_runs
            WHERE stage=? AND id NOT IN (
              SELECT id FROM stage_runs WHERE stage=? ORDER BY id DESC LIMIT 50
            )
            """,
            (stage, stage),
        )
        self.conn.commit()

    def latest_stage_detail(self, stage: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT detail_json FROM stage_runs WHERE stage=? ORDER BY id DESC LIMIT 1",
            (stage,),
        ).fetchone()
        if not row or not row["detail_json"]:
            return {}
        try:
            detail = json.loads(row["detail_json"])
        except json.JSONDecodeError:
            return {}
        return detail if isinstance(detail, dict) else {}

    def stage_completed(self, stage: str) -> bool:
        row = self.conn.execute(
            "SELECT status FROM stage_runs WHERE stage=? ORDER BY id DESC LIMIT 1",
            (stage,),
        ).fetchone()
        return bool(row and row["status"] in ("ok", "skipped"))

    def active_cves(self, config: Any | None = None) -> list[str]:
        if config is not None and getattr(config, "cves", None):
            return list(getattr(config, "cves"))
        return []

    def scope_sql(self, alias: str, config: Any | None = None) -> tuple[str, list[str]]:
        cves = self.active_cves(config)
        if not cves:
            return "", []
        placeholders = ",".join("?" for _ in cves)
        return f" AND {alias}.cve_id IN ({placeholders})", cves

    def selected_fix_count_with_functions(self, config: Any | None = None) -> int:
        scope, params = self.scope_sql("f", config)
        return self.conn.execute(
            f"""
            SELECT COUNT(DISTINCT f.cve_id)
            FROM fix_candidates f
            JOIN source_functions s ON s.cve_id=f.cve_id AND s.commit_hash=f.commit_hash AND s.active=1
            WHERE f.selected=1{scope}
            """,
            params,
        ).fetchone()[0]


    def selected_testset_count(self, config: Any | None = None) -> int:
        scope, params = self.scope_sql("testset_entries", config)
        return self.conn.execute(
            f"SELECT COUNT(*) FROM testset_entries WHERE status='selected'{scope}",
            params,
        ).fetchone()[0]


    def debug_split_satisfied(self, config: Any | None = None) -> bool:
        if config is None:
            return True
        if self.testset_missing_target(config):
            return False
        compiler, opt, build_profile = self.build_filter(config)
        scope, scope_params = self.scope_sql("t", config)
        rows = self.conn.execute(
            f"""
            SELECT DISTINCT a.path, a.debug_path
            FROM testset_entries t
            JOIN target_mappings m ON m.testset_entry_id=t.id AND m.status='ok'
            JOIN target_artifacts a ON a.id=m.artifact_id
            JOIN build_variants v ON v.id=a.build_variant_id
            WHERE t.status='selected' AND t.label IN ('vuln','patch')
              AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=?
              AND a.status='ok'{scope}
            """,
            (self.architecture_filter(config), compiler, opt, build_profile, *scope_params),
        )
        for row in rows:
            if not row["path"] or not row["debug_path"]:
                return False
            path = self.resolve_path(row["path"])
            debug_path = self.resolve_path(row["debug_path"])
            if (
                not path.exists()
                or not debug_path.exists()
                or not matches_elf_architecture(path, self.architecture_filter(config))
                or not matches_elf_architecture(debug_path, self.architecture_filter(config))
            ):
                return False
        return True

    def variant_export_satisfied(self, config: Any) -> bool:
        suffix = getattr(config, "build_variant", "")
        if not suffix:
            return False
        names = (
            f"testset.{suffix}.json",
            f"testset.pick.{suffix}.json",
            f"groundtruth.{suffix}.json",
            f"not_affected.{suffix}.json",
            f"groundtruth_with_not_affected.{suffix}.json",
            f"not_affected_candidates.{suffix}.json",
            f"affectedness_audit_summary.{suffix}.json",
        )
        return all((config.exports_dir / name).is_file() for name in names)

    def export_satisfied(self, config: Any) -> bool:
        project = getattr(config, "project", "")
        if not project:
            return False
        if self.architecture_filter(config) != "x86_64":
            names = (f"{project}_metadata.{config.architecture}.json", f"{project}_reference.{config.architecture}.json")
        else:
            names = (
                f"{project}_metadata.json",
                f"{project}_reference.json",
                "testset.json",
                "testset.pick.json",
                "groundtruth.json",
                "not_affected.json",
                "groundtruth_with_not_affected.json",
                "not_affected_candidates.json",
                "affectedness_audit_summary.json",
            )
        return all((config.exports_dir / name).is_file() for name in names)

    def stage_satisfied(self, stage: str, config: Any | None = None) -> bool:
        if stage in {"git_update", "releases"}:
            return self.stage_completed(stage)
        if stage == "RCA":
            if config is None or getattr(config, "metadata_mode", "skip") == "skip":
                return self.stage_completed(stage)
            mode = getattr(config, "metadata_mode", "")
            if mode not in {"source", "behavior"}:
                return self.stage_completed(stage)
            expected = self.rca_expected_cves(config)
            if not expected:
                return self.stage_completed(stage)
            source_complete = not self.cves_missing_rca(config, "source")
            if mode == "source":
                return source_complete
            return source_complete and not self.cves_missing_rca(config, "behavior")
        if not self.stage_completed(stage):
            return False
        if stage == "cve_metadata":
            return not self.missing_requested_cves()
        if stage == "cve2diff":
            return not self.cves_missing_selected_fix(config)
        if stage == "source_analysis":
            return not self.selected_fixes_missing_source(config)
        if stage == "reference_build":
            expected = self.selected_fix_count_with_functions(config)
            return expected > 0 and not self.selected_fixes_missing_reference(config)
        if stage == "testset":
            if config is not None:
                detail = self.latest_stage_detail("testset")
                if detail.get("strategy") != getattr(config, "testset_strategy", ""):
                    return False
                if detail.get("affected_filter") != "nvd-configurations":
                    return False
                try:
                    if int(detail.get("count", 0)) != int(getattr(config, "testset_count", 0)):
                        return False
                except (TypeError, ValueError):
                    return False
            return not self.references_missing_testset(config)
        if stage == "target_build":
            expected = self.selected_testset_count(config)
            return expected > 0 and not self.testset_missing_target(config)
        if stage == "not_affected_review":
            if config is not None:
                detail = self.latest_stage_detail("not_affected_review")
                if detail.get("policy") != "affectedness-audit-v2":
                    return False
            return not self.pending_not_affected_candidates(config, policy="affectedness-audit-v2")
        if stage == "debug_split":
            return self.debug_split_satisfied(config)
        if stage == "variant_export":
            return config is not None and self.variant_export_satisfied(config)
        if stage == "export":
            return config is not None and self.export_satisfied(config)
        return True

    def build_filter(self, config: Any | None = None, build_profile: str = "") -> tuple[str, str, str]:
        if config is None:
            return "", "", build_profile
        return getattr(config, "compiler", "") or "", getattr(config, "opt", "") or "", build_profile

    def architecture_filter(self, config: Any | None = None) -> str:
        return getattr(config, "architecture", "x86_64") if config is not None else "x86_64"

    def reference_filter(self, config: Any | None = None) -> tuple[str, str, str]:
        return REFERENCE_COMPILER, REFERENCE_OPT, REFERENCE_BUILD_PROFILE

    def requested_cves(self) -> list[str]:
        row = self.conn.execute("SELECT value FROM project WHERE key='build_config'").fetchone()
        if not row:
            return []
        try:
            config = json.loads(row["value"])
        except json.JSONDecodeError:
            return []
        return list(config.get("cves") or [])

    def missing_requested_cves(self) -> list[str]:
        missing = []
        for cve_id in self.requested_cves():
            row = self.conn.execute("SELECT 1 FROM cves WHERE cve_id=? AND selected=1", (cve_id,)).fetchone()
            if not row:
                missing.append(cve_id)
        return missing

    def cves_missing_selected_fix(self, config: Any | None = None) -> list[str]:
        scope, params = self.scope_sql("c", config)
        rows = self.conn.execute(
            f"""
            SELECT c.cve_id
            FROM cves c
            LEFT JOIN fix_candidates f ON f.cve_id=c.cve_id AND f.selected=1
            WHERE c.selected=1{scope} AND f.cve_id IS NULL
            ORDER BY c.cve_id
            """,
            params,
        )
        return [r["cve_id"] for r in rows]

    def selected_fixes_missing_source(self, config: Any | None = None) -> list[str]:
        scope, params = self.scope_sql("f", config)
        rows = self.conn.execute(
            f"""
            SELECT f.cve_id
            FROM fix_candidates f
            LEFT JOIN source_functions s ON s.cve_id=f.cve_id AND s.commit_hash=f.commit_hash AND s.active=1
            WHERE f.selected=1{scope} AND s.cve_id IS NULL
            GROUP BY f.cve_id
            ORDER BY f.cve_id
            """,
            params,
        )
        return [r["cve_id"] for r in rows]

    def selected_fixes_missing_reference(self, config: Any | None = None) -> list[str]:
        scope, scope_params = self.scope_sql("f", config)
        rows = self.conn.execute(
            f"""
            SELECT DISTINCT f.cve_id
            FROM fix_candidates f
            JOIN source_functions s ON s.cve_id=f.cve_id AND s.commit_hash=f.commit_hash AND s.active=1
            WHERE f.selected=1{scope}
            ORDER BY f.cve_id
            """,
            scope_params,
        )
        missing = []
        for row in rows:
            reference = self.reference_for_cve(row["cve_id"], config)
            if not self._reference_is_usable(row["cve_id"], reference, config):
                missing.append(row["cve_id"])
        return missing


    def references_missing_testset(self, config: Any | None = None) -> list[str]:
        refs = self.references(config)
        missing = []
        for ref in refs:
            row = self.conn.execute(
                "SELECT 1 FROM testset_entries WHERE cve_id=? LIMIT 1",
                (ref["cve_id"],),
            ).fetchone()
            if not row:
                missing.append(ref["cve_id"])
        return sorted(missing)

    def testset_missing_target(self, config: Any | None = None) -> list[str]:
        compiler, opt, build_profile = self.build_filter(config)
        scope, scope_params = self.scope_sql("t", config)
        rows = self.conn.execute(
            f"""
            SELECT t.cve_id, t.version, t.binary_name, a.path
            FROM testset_entries t
            LEFT JOIN target_mappings m ON m.id=(
              SELECT matching.id
              FROM target_mappings matching
              JOIN target_artifacts matching_artifact ON matching_artifact.id=matching.artifact_id
              JOIN build_variants matching_variant ON matching_variant.id=matching_artifact.build_variant_id
              WHERE matching.testset_entry_id=t.id
                AND matching.status='ok'
                AND matching_artifact.status='ok'
                AND matching_variant.architecture=?
                AND matching_variant.compiler=?
                AND matching_variant.opt=?
                AND matching_variant.build_profile=?
              ORDER BY matching.updated_at DESC, matching.id DESC
              LIMIT 1
            )
            LEFT JOIN target_artifacts a ON a.id=m.artifact_id
            WHERE t.status='selected'{scope}
            ORDER BY t.cve_id, t.label, t.tag
            """,
            (self.architecture_filter(config), compiler, opt, build_profile, *scope_params),
        )
        missing: set[str] = set()
        for row in rows:
            path = self.resolve_path(row["path"]) if row["path"] else None
            if path is None or not path.exists() or not matches_elf_architecture(path, self.architecture_filter(config)):
                missing.add(row["cve_id"])
                continue
            if config is not None and path.name != config.target_binary_name(row["version"], row["binary_name"]):
                missing.add(row["cve_id"])
        return sorted(missing)


    def cve_base_ready(self, cve_id: str, config: Any | None = None) -> bool:
        fix = self.conn.execute(
            """SELECT f.commit_hash
               FROM cves c JOIN fix_candidates f ON f.cve_id=c.cve_id AND f.selected=1
               WHERE c.cve_id=? AND c.selected=1""",
            (cve_id,),
        ).fetchone()
        if not fix:
            return False
        if not self.conn.execute(
            "SELECT 1 FROM source_functions WHERE cve_id=? AND commit_hash=? AND active=1 LIMIT 1",
            (cve_id, fix["commit_hash"]),
        ).fetchone():
            return False
        reference = self.conn.execute(
            """SELECT r.vuln_path,r.patch_path,r.functions_json
               FROM reference_binaries r JOIN build_variants v ON v.id=r.build_variant_id
               WHERE r.cve_id=? AND r.status='ok'
                 AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=?""",
            (cve_id, self.architecture_filter(config), REFERENCE_COMPILER, REFERENCE_OPT, REFERENCE_BUILD_PROFILE),
        ).fetchone()
        if not self._reference_is_usable(cve_id, reference, config):
            return False
        return self.conn.execute(
            "SELECT 1 FROM testset_entries WHERE cve_id=? AND status='selected' LIMIT 1",
            (cve_id,),
        ).fetchone() is not None

    def classify_requested_cves(self, cve_ids: Iterable[str], config: Any | None = None) -> tuple[list[str], list[str]]:
        variant_only = []
        bootstrap = []
        for cve_id in cve_ids:
            (variant_only if self.cve_base_ready(cve_id, config) else bootstrap).append(cve_id)
        return variant_only, bootstrap
