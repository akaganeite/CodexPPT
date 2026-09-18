from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from builder.architecture import matches_elf_architecture
from builder.db_schema import initialize_database
from builder.db_resume import ResumeStateMixin


RCA_ALLOWLIST_SCHEMA = "related_file_allowlist.v2"


class ProjectDB(ResumeStateMixin):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        initialize_database(self.conn, path)

    def _variant_id(self, compiler: str, opt: str, build_profile: str, architecture: str = "x86_64") -> int:
        self.conn.execute(
            "INSERT OR IGNORE INTO build_variants(architecture,compiler,opt,build_profile) VALUES(?,?,?,?)",
            (architecture or "x86_64", compiler or "", opt or "", build_profile or ""),
        )
        return self.conn.execute(
            "SELECT id FROM build_variants WHERE architecture=? AND compiler=? AND opt=? AND build_profile=?",
            (architecture or "x86_64", compiler or "", opt or "", build_profile or ""),
        ).fetchone()[0]

    def resolve_path(self, value: str | None) -> Path:
        path = Path(value or "")
        return path if path.is_absolute() else self.path.parent / path

    def stored_path(self, value: str | Path | None) -> str:
        if value is None:
            return ""
        path = Path(value)
        if not path.is_absolute():
            return str(path)
        try:
            return str(path.relative_to(self.path.parent))
        except ValueError:
            try:
                return str(path.resolve().relative_to(self.path.parent.resolve()))
            except ValueError:
                return str(path)

    def close(self) -> None:
        self.conn.close()

    def set_project_value(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO project(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value, ensure_ascii=False)),
        )
        self.conn.commit()


    def upsert_cve(self, item: dict[str, Any], selected: bool = False) -> None:
        cve_id = item["id"]
        self.conn.execute(
            """
            INSERT INTO cves(cve_id, raw_json, summary, cwe_json, references_json, published, last_modified, selected, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'raw')
            ON CONFLICT(cve_id) DO UPDATE SET
              raw_json=excluded.raw_json,
              summary=excluded.summary,
              cwe_json=excluded.cwe_json,
              references_json=excluded.references_json,
              published=excluded.published,
              last_modified=excluded.last_modified,
              selected=max(cves.selected, excluded.selected)
            """,
            (
                cve_id,
                json.dumps(item, ensure_ascii=False),
                item.get("summary", ""),
                json.dumps(item.get("cwe", []), ensure_ascii=False),
                json.dumps(item.get("references", []), ensure_ascii=False),
                item.get("published", ""),
                item.get("last_modified", ""),
                1 if selected else 0,
            ),
        )
        self.conn.commit()


    def selected_cves(self, config: Any | None = None) -> list[sqlite3.Row]:
        scope, params = self.scope_sql("cves", config)
        return list(
            self.conn.execute(
                f"SELECT * FROM cves WHERE selected=1{scope} ORDER BY published DESC, cve_id DESC",
                params,
            )
        )

    def upsert_fix_candidate(self, cve_id: str, candidate: dict[str, Any], diff_path: str = "", patch_id: str = "") -> None:
        self.conn.execute(
            """
            INSERT INTO fix_candidates(cve_id, commit_hash, parent_hash, relation, confidence, evidence_json, source, selected, diff_path, patch_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id, commit_hash) DO UPDATE SET
              parent_hash=excluded.parent_hash,
              relation=excluded.relation,
              confidence=excluded.confidence,
              evidence_json=excluded.evidence_json,
              source=excluded.source,
              selected=excluded.selected,
              diff_path=excluded.diff_path,
              patch_id=excluded.patch_id,
              status=excluded.status
            """,
            (
                cve_id,
                candidate["commit"],
                candidate.get("parent", ""),
                candidate.get("relation", "unknown"),
                float(candidate.get("confidence", 0.0)),
                json.dumps(candidate.get("evidence", []), ensure_ascii=False),
                candidate.get("source", "codex"),
                1 if candidate.get("selected") else 0,
                self.stored_path(diff_path),
                patch_id,
                candidate.get("status", "candidate"),
            ),
        )
        self.conn.commit()

    def selected_fixes(self, config: Any | None = None) -> list[dict[str, Any]]:
        scope, params = self.scope_sql("c", config)
        rows = self.conn.execute(
                f"""
                SELECT c.*, f.commit_hash, f.parent_hash, f.diff_path
                FROM cves c JOIN fix_candidates f ON c.cve_id=f.cve_id
                WHERE c.selected=1{scope} AND f.selected=1
                ORDER BY c.published DESC, c.cve_id DESC
                """,
                params,
            )
        return [{**dict(row), "diff_path": str(self.resolve_path(row["diff_path"])) if row["diff_path"] else ""} for row in rows]

    def rca_expected_cves(self, config: Any | None = None) -> list[str]:
        return sorted({row["cve_id"] for row in self.selected_fixes(config)})

    def _rca_artifact_complete(self, mode: str, cve_id: str, artifact_path: str, detail_json: str = "") -> bool:
        if not artifact_path:
            return False
        path = self.resolve_path(artifact_path)
        if not path.exists():
            return False
        if mode == "source":
            try:
                source = json.loads(path.read_text(encoding="utf-8"))
                detail = json.loads(detail_json or "{}")
            except (OSError, json.JSONDecodeError):
                return False
            source_item = source.get(cve_id) if isinstance(source, dict) else None
            if not isinstance(source_item, dict) or not source_item:
                return False
            if not isinstance(detail, dict) or detail.get("related_file_allowlist_schema") != RCA_ALLOWLIST_SCHEMA:
                return False
            allowlist_path = self.resolve_path(detail.get("related_file_allowlist", ""))
            if not allowlist_path.exists():
                return False
            try:
                allowlist = json.loads(allowlist_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return False
            item = allowlist.get("cves", {}).get(cve_id) if isinstance(allowlist, dict) else None
            return (
                isinstance(allowlist, dict)
                and allowlist.get("schema") == RCA_ALLOWLIST_SCHEMA
                and isinstance(item, dict)
            )
        if mode != "behavior":
            return True
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        item = data.get(cve_id) if isinstance(data, dict) else None
        if not isinstance(item, dict):
            return False
        if not item.get("root_cause_analysis") or not item.get("patch_intent_analysis"):
            return False
        anchors = item.get("function_anchors")
        if not isinstance(anchors, dict):
            return False
        patch_source = item.get("patch_source")
        if not (
            isinstance(patch_source, dict)
            and isinstance(patch_source.get("commit"), str)
            and isinstance(patch_source.get("locations"), list)
        ):
            return False
        for function in self.functions_for_cve(cve_id):
            entries = anchors.get(function)
            if not isinstance(entries, list) or len(entries) < 5:
                return False
        return True

    def cves_missing_rca(self, config: Any | None, mode: str) -> list[str]:
        expected = self.rca_expected_cves(config)
        if not expected:
            return []
        placeholders = ",".join("?" for _ in expected)
        rows = self.conn.execute(
            f"""
            SELECT cve_id, artifact_path, detail_json
            FROM rca_statuses
            WHERE mode=? AND status='ok' AND cve_id IN ({placeholders})
            """,
            (mode, *expected),
        )
        ok = set()
        for row in rows:
            artifact_path = row["artifact_path"] or ""
            if self._rca_artifact_complete(mode, row["cve_id"], artifact_path, row["detail_json"] or ""):
                ok.add(row["cve_id"])
        return [cve_id for cve_id in expected if cve_id not in ok]


    def upsert_many_rca_statuses(self, items: Iterable[dict[str, Any]]) -> None:
        rows = [
            (
                item["cve_id"],
                item["mode"],
                item["status"],
                self.stored_path(item.get("artifact_path", "")),
                json.dumps(item.get("detail", {}) or {}, ensure_ascii=False, default=str),
            )
            for item in items
        ]
        if not rows:
            return
        self.conn.executemany(
            """
            INSERT INTO rca_statuses(cve_id, mode, status, artifact_path, detail_json, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(cve_id, mode) DO UPDATE SET
              status=excluded.status,
              artifact_path=excluded.artifact_path,
              detail_json=excluded.detail_json,
              updated_at=CURRENT_TIMESTAMP
            """,
            rows,
        )
        self.conn.commit()

    def replace_source_functions(self, cve_id: str, commit: str, functions: list[dict[str, Any]]) -> None:
        self.conn.execute("DELETE FROM source_functions WHERE cve_id=? AND commit_hash=?", (cve_id, commit))
        self.conn.executemany(
            """
            INSERT OR REPLACE INTO source_functions(cve_id, commit_hash, function, change_type, file_path, active)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    cve_id,
                    commit,
                    item.get("function", ""),
                    item.get("type", "modified"),
                    item.get("file", ""),
                    1,
                )
                for item in functions
                if item.get("function")
            ],
        )
        self.conn.commit()

    def functions_for_cve(self, cve_id: str, include_added: bool = True) -> list[str]:
        if include_added:
            rows = self.conn.execute(
                "SELECT DISTINCT function FROM source_functions WHERE cve_id=? AND active=1 ORDER BY function",
                (cve_id,),
            )
        else:
            rows = self.conn.execute(
                """
                SELECT DISTINCT function
                FROM source_functions
                WHERE cve_id=? AND active=1 AND COALESCE(change_type, '') != 'added'
                ORDER BY function
                """,
                (cve_id,),
            )
        return [r["function"] for r in rows]

    def function_details_for_cve(self, cve_id: str) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT function, change_type, file_path
                FROM source_functions
                WHERE cve_id=? AND active=1
                ORDER BY function, file_path
                """,
                (cve_id,),
            )
        )


    def upsert_reference(self, item: dict[str, Any]) -> None:
        variant_id = self._variant_id(
            item.get("compiler", ""),
            item.get("opt", ""),
            item.get("build_profile", ""),
            item.get("architecture", "x86_64"),
        )
        self.conn.execute(
            """
            INSERT INTO reference_binaries(
              cve_id,build_variant_id,vuln_commit,patch_commit,binary_name,vuln_path,patch_path,
              functions_json,status,report_json,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
            ON CONFLICT(cve_id,build_variant_id) DO UPDATE SET
              vuln_commit=excluded.vuln_commit,patch_commit=excluded.patch_commit,
              binary_name=excluded.binary_name,vuln_path=excluded.vuln_path,patch_path=excluded.patch_path,
              functions_json=excluded.functions_json,status=excluded.status,report_json=excluded.report_json,
              updated_at=CURRENT_TIMESTAMP
            """,
            (item["cve_id"], variant_id, item.get("vuln_commit", ""), item.get("patch_commit", ""),
             item.get("binary_name", ""), self.stored_path(item.get("vuln_path")), self.stored_path(item.get("patch_path")),
             json.dumps(item.get("functions", []), ensure_ascii=False), item.get("status", "ok"),
             json.dumps(item.get("report", {}), ensure_ascii=False)),
        )
        self.conn.commit()

    def invalidate_reference(self, reference_id: int, validation: dict[str, Any]) -> None:
        row = self.conn.execute(
            "SELECT report_json FROM reference_binaries WHERE id=?",
            (reference_id,),
        ).fetchone()
        if row is None:
            return
        try:
            report = json.loads(row["report_json"] or "{}")
        except json.JSONDecodeError:
            report = {}
        if not isinstance(report, dict):
            report = {}
        report["reference_validation"] = validation
        self.conn.execute(
            """
            UPDATE reference_binaries
            SET status='failed',report_json=?,updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (json.dumps(report, ensure_ascii=False), reference_id),
        )
        self.conn.commit()

    def references(self, config: Any | None = None) -> list[dict[str, Any]]:
        where = "r.status='ok'"
        params: list[Any] = []
        if config is not None:
            compiler, opt, build_profile = self.reference_filter(config)
            where += " AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=?"
            params.extend((self.architecture_filter(config), compiler, opt, build_profile))
            scope, scope_params = self.scope_sql("r", config)
            where += scope
            params.extend(scope_params)
        rows = self.conn.execute(
            f"""SELECT r.*,v.architecture,v.compiler,v.opt,v.build_profile
                FROM reference_binaries r JOIN build_variants v ON v.id=r.build_variant_id
                WHERE {where} ORDER BY r.cve_id""", params)
        out = []
        for row in rows:
            vuln_path = self.resolve_path(row["vuln_path"])
            patch_path = self.resolve_path(row["patch_path"])
            if config is not None and (
                not matches_elf_architecture(vuln_path, self.architecture_filter(config))
                or not matches_elf_architecture(patch_path, self.architecture_filter(config))
            ):
                continue
            out.append({**dict(row), "vuln_path": str(vuln_path), "patch_path": str(patch_path)})
        return out

    def reference_for_cve(self, cve_id: str, config: Any | None = None) -> dict[str, Any] | None:
        compiler, opt, build_profile = self.reference_filter(config)
        row = self.conn.execute(
            """SELECT r.*,v.architecture,v.compiler,v.opt,v.build_profile
               FROM reference_binaries r JOIN build_variants v ON v.id=r.build_variant_id
               WHERE r.cve_id=? AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=? AND r.status='ok'
               ORDER BY r.updated_at DESC LIMIT 1""",
            (cve_id, self.architecture_filter(config), compiler, opt, build_profile),
        ).fetchone()
        if row is None:
            return None
        return {**dict(row), "vuln_path": str(self.resolve_path(row["vuln_path"])), "patch_path": str(self.resolve_path(row["patch_path"]))}

    def upsert_release(self, item: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO releases(tag, commit_sha, date, version, norm_tag)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(tag) DO UPDATE SET
              commit_sha=excluded.commit_sha,
              date=excluded.date,
              version=excluded.version,
              norm_tag=excluded.norm_tag
            """,
            (
                item.get("tag", ""),
                item.get("commit_sha", ""),
                item.get("date", ""),
                item.get("version", ""),
                item.get("norm_tag", item.get("version", "")),
            ),
        )
        self.conn.commit()

    def releases(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM releases WHERE norm_tag!='' ORDER BY date"))

    def replace_testset_entries(self, cve_id: str, entries: list[dict[str, Any]]) -> None:
        requested: dict[tuple[str, str, str], dict[str, Any]] = {}
        for item in entries:
            identity = (item["label"], item["tag"], item.get("binary_name", ""))
            if identity in requested:
                raise ValueError(f"duplicate testset entry for {cve_id}: {identity}")
            requested[identity] = item

        existing_rows = self.conn.execute(
            "SELECT id,label,tag,binary_name FROM testset_entries WHERE cve_id=?", (cve_id,)
        ).fetchall()
        existing = {(row["label"], row["tag"], row["binary_name"]): row for row in existing_rows}

        # Keep unchanged rows in place so their target mappings and reviews survive a reselection.
        for identity, row in existing.items():
            if identity not in requested:
                self.conn.execute("DELETE FROM testset_entries WHERE id=?", (row["id"],))
        for identity, item in requested.items():
            row = existing.get(identity)
            if row:
                self.conn.execute(
                    """UPDATE testset_entries
                       SET version=?,reason=?,status=?,updated_at=CURRENT_TIMESTAMP
                       WHERE id=?""",
                    (item["version"], item.get("reason", ""), item.get("status", "selected"), row["id"]),
                )
                continue
            self.conn.execute(
                """INSERT INTO testset_entries(cve_id,label,version,tag,binary_name,reason,status)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    cve_id,
                    item["label"],
                    item["version"],
                    item["tag"],
                    item.get("binary_name", ""),
                    item.get("reason", ""),
                    item.get("status", "selected"),
                ),
            )
        self.conn.commit()

    def testset_entries(self, config: Any | None = None) -> list[sqlite3.Row]:
        scope, params = self.scope_sql("testset_entries", config)
        return list(
            self.conn.execute(
                f"SELECT * FROM testset_entries WHERE 1=1{scope} ORDER BY cve_id, label, tag",
                params,
            )
        )

    def upsert_target_artifact(self, item: dict[str, Any]) -> int:
        variant_id = self._variant_id(
            item.get("compiler", ""),
            item.get("opt", ""),
            item.get("build_profile", ""),
            item.get("architecture", "x86_64"),
        )
        self.conn.execute(
            """INSERT INTO target_artifacts(tag,version,binary_name,build_variant_id,path,status,report_json,updated_at)
               VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
               ON CONFLICT(tag,binary_name,build_variant_id) DO UPDATE SET
                 version=excluded.version,path=excluded.path,status=excluded.status,
                 report_json=excluded.report_json,updated_at=CURRENT_TIMESTAMP""",
            (item["tag"], item.get("version", ""), item["binary_name"], variant_id,
             self.stored_path(item.get("path")), item.get("status", "ok"), json.dumps(item.get("report", {}), ensure_ascii=False)),
        )
        row = self.conn.execute("SELECT id FROM target_artifacts WHERE tag=? AND binary_name=? AND build_variant_id=?", (item["tag"], item["binary_name"], variant_id)).fetchone()
        self.conn.commit()
        return int(row["id"])

    def target_artifact_for_task(
        self,
        project: str,
        tag: str,
        binary_name: str,
        compiler: str,
        opt: str,
        build_profile: str = "",
        architecture: str = "x86_64",
    ) -> dict[str, Any] | None:
        row = self.conn.execute(
            """SELECT a.*,v.architecture,v.compiler,v.opt,v.build_profile
               FROM target_artifacts a JOIN build_variants v ON v.id=a.build_variant_id
               WHERE a.tag=? AND a.binary_name=? AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=? AND a.status='ok'""",
            (tag, binary_name, architecture or "x86_64", compiler, opt, build_profile),
        ).fetchone()
        return {**dict(row), "path": str(self.resolve_path(row["path"])), "debug_path": str(self.resolve_path(row["debug_path"])) if row["debug_path"] else ""} if row else None

    def upsert_target_mapping(self, item: dict[str, Any]) -> None:
        testset = self.conn.execute(
            "SELECT id FROM testset_entries WHERE cve_id=? AND label=? AND tag=? AND binary_name=?",
            (item["cve_id"], item.get("label", ""), item.get("tag", ""), item.get("binary_name", "")),
        ).fetchone()
        if testset is None:
            raise ValueError(f"target mapping has no testset entry: {item['cve_id']} {item.get('label','')} {item.get('tag','')}")
        self.conn.execute(
            """INSERT INTO target_mappings(testset_entry_id,artifact_id,status,report_json,updated_at)
               VALUES(?,?,?,?,CURRENT_TIMESTAMP)
               ON CONFLICT(testset_entry_id,artifact_id) DO UPDATE SET
                 status=excluded.status,report_json=excluded.report_json,updated_at=CURRENT_TIMESTAMP""",
            (testset["id"], item["artifact_id"], item.get("status", "ok"), json.dumps(item.get("report", {}), ensure_ascii=False)),
        )
        self.conn.commit()

    def target_mapping_for_testset(self, row, config: Any | None = None, build_profile: str = "") -> dict[str, Any] | None:
        compiler, opt, build_profile = self.build_filter(config, build_profile)
        result = self.conn.execute(
            """SELECT m.*,a.path,a.debug_path,a.status AS artifact_status,
                      v.architecture AS artifact_architecture,v.compiler AS artifact_compiler,v.opt AS artifact_opt,v.build_profile
               FROM target_mappings m JOIN target_artifacts a ON a.id=m.artifact_id
               JOIN build_variants v ON v.id=a.build_variant_id
               WHERE m.testset_entry_id=? AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=?
                 AND m.status='ok' AND a.status='ok'""",
            (row["id"], self.architecture_filter(config), compiler, opt, build_profile),
        ).fetchone()
        return {**dict(result), "path": str(self.resolve_path(result["path"])), "debug_path": str(self.resolve_path(result["debug_path"])) if result["debug_path"] else ""} if result else None

    def selected_target_candidates(self, config: Any | None = None) -> list[dict[str, Any]]:
        compiler, opt, build_profile = self.build_filter(config)
        scope, scope_params = self.scope_sql("t", config)
        rows = self.conn.execute(
            f"""SELECT t.id AS testset_entry_id,m.id AS target_mapping_id,a.id AS artifact_id,t.cve_id,t.label,t.tag,t.version,t.binary_name,
                       a.path,a.debug_path,a.report_json AS artifact_report_json,v.architecture,v.compiler,v.opt,v.build_profile
                FROM testset_entries t JOIN target_mappings m ON m.testset_entry_id=t.id AND m.status='ok'
                JOIN target_artifacts a ON a.id=m.artifact_id AND a.status='ok'
                JOIN build_variants v ON v.id=a.build_variant_id
                WHERE t.status='selected' AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=?{scope}
                ORDER BY t.cve_id,t.label,t.tag,t.binary_name""",
            (self.architecture_filter(config), compiler, opt, build_profile, *scope_params),
        )
        out = []
        for row in rows:
            target_path = self.resolve_path(row["path"])
            if not matches_elf_architecture(target_path, self.architecture_filter(config)):
                continue
            out.append(
                {
                    **dict(row),
                    "target_path": str(target_path),
                    "debug_path": str(self.resolve_path(row["debug_path"])) if row["debug_path"] else "",
                }
            )
        return out

    def global_not_affected_candidates(self, config: Any | None = None) -> list[dict[str, Any]]:
        scope, params = self.scope_sql("t", config)
        architecture = self.architecture_filter(config)
        rows = self.conn.execute(
            f"""
            SELECT t.id AS testset_entry_id,t.cve_id,t.label,t.tag,t.version,t.binary_name,
                   a.id AS artifact_id,a.path,a.debug_path,a.report_json AS artifact_report_json,v.architecture,v.compiler,v.opt,v.build_profile
            FROM testset_entries t
            JOIN target_mappings m ON m.id=(
              SELECT candidate.id
              FROM target_mappings candidate
              JOIN target_artifacts candidate_artifact ON candidate_artifact.id=candidate.artifact_id
              JOIN build_variants candidate_variant ON candidate_variant.id=candidate_artifact.build_variant_id
              WHERE candidate.testset_entry_id=t.id
                AND candidate.status='ok' AND candidate_artifact.status='ok'
                AND candidate_variant.architecture=?
              ORDER BY candidate.updated_at DESC,candidate.id DESC
              LIMIT 1
            )
            JOIN target_artifacts a ON a.id=m.artifact_id
            JOIN build_variants v ON v.id=a.build_variant_id
            WHERE t.status='selected'{scope}
            ORDER BY t.cve_id,t.label,t.tag,t.binary_name
            """,
            (architecture, *params),
        )
        out = []
        for row in rows:
            target_path = self.resolve_path(row["path"])
            if not matches_elf_architecture(target_path, architecture):
                continue
            out.append(
                {
                    **dict(row),
                    "target_path": str(target_path),
                    "debug_path": str(self.resolve_path(row["debug_path"])) if row["debug_path"] else "",
                    "missing_functions": [],
                    "missing_functions_json": "[]",
                    "candidate_type": "affectedness_audit",
                    "reference_functions": [],
                    "reason": "selected target affectedness audit",
                    "report": {},
                }
            )
        return out

    def variant_export_rows(self, config: Any) -> list[dict[str, Any]]:
        compiler, opt, build_profile = self.build_filter(config)
        rows = self.conn.execute(
            """
            SELECT t.cve_id,t.label,t.tag,t.version,t.binary_name,a.path,a.debug_path,v.architecture
            FROM testset_entries t
            JOIN target_mappings m ON m.testset_entry_id=t.id AND m.status='ok'
            JOIN target_artifacts a ON a.id=m.artifact_id AND a.status='ok'
            JOIN build_variants v ON v.id=a.build_variant_id
            WHERE t.status='selected' AND t.label IN ('vuln','patch')
              AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=?
            ORDER BY t.cve_id,t.label,t.tag,t.binary_name
            """,
            (self.architecture_filter(config), compiler, opt, build_profile),
        )
        out = []
        for row in rows:
            if not row["path"] or not row["debug_path"]:
                continue
            path = self.resolve_path(row["path"])
            debug_path = self.resolve_path(row["debug_path"])
            if (
                not path.exists()
                or not debug_path.exists()
                or not matches_elf_architecture(path, self.architecture_filter(config))
                or not matches_elf_architecture(debug_path, self.architecture_filter(config))
            ):
                continue
            out.append({**dict(row), "path": str(path), "debug_path": str(debug_path)})
        return out


    def not_affected_candidates(self, config: Any | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in self.selected_target_candidates(config):
            out.append(
                {
                    **item,
                    "missing_functions": [],
                    "missing_functions_json": "[]",
                    "candidate_type": "affectedness_audit",
                    "reference_functions": [],
                    "reason": "selected target affectedness audit",
                    "report": {},
                }
            )
        return out


    def not_affected_review_for_candidate(
        self, candidate: dict[str, Any], policy: str | None = None, fallback_policies: tuple[str, ...] = ()
    ) -> sqlite3.Row | None:
        architecture = candidate.get("architecture", "x86_64") or "x86_64"
        testset_entry_id = candidate.get("testset_entry_id")
        if testset_entry_id is None:
            row = self.conn.execute(
                "SELECT id FROM testset_entries WHERE cve_id=? AND label=? AND tag=? AND binary_name=?",
                (candidate["cve_id"], candidate.get("label", ""), candidate["tag"], candidate["binary_name"]),
            ).fetchone()
            testset_entry_id = row["id"] if row else None
        if testset_entry_id is None:
            return None
        select_sql = """
            SELECT r.*,v.architecture AS artifact_architecture,v.compiler,v.opt,v.build_profile,a.path AS target_path
            FROM affectedness_reviews r
            LEFT JOIN target_artifacts a ON a.id=r.reviewed_artifact_id
            LEFT JOIN build_variants v ON v.id=a.build_variant_id
        """
        if policy is None:
            return self.conn.execute(
                select_sql + " WHERE r.testset_entry_id=? AND r.architecture=? ORDER BY r.updated_at DESC LIMIT 1",
                (testset_entry_id, architecture),
            ).fetchone()
        policies = (policy, *tuple(item for item in fallback_policies if item and item != policy))
        placeholders = ",".join("?" for _ in policies)
        order = " ".join(f"WHEN ? THEN {index}" for index, _ in enumerate(policies))
        return self.conn.execute(
            select_sql
            + f" WHERE r.testset_entry_id=? AND r.architecture=? AND r.policy IN ({placeholders})"
            + f" ORDER BY CASE r.policy {order} ELSE {len(policies)} END, r.updated_at DESC LIMIT 1",
            (testset_entry_id, architecture, *policies, *policies),
        ).fetchone()

    def pending_not_affected_candidates(self, config: Any | None = None, policy: str = "affectedness-audit-v1") -> list[dict[str, Any]]:
        pending = []
        for candidate in self.not_affected_candidates(config):
            review = self.not_affected_review_for_candidate(candidate, policy=policy)
            if not review or review["status"] == "failed":
                pending.append(candidate)
        return pending

    def upsert_not_affected_review(self, item: dict[str, Any]) -> None:
        architecture = item.get("architecture", "x86_64") or "x86_64"
        testset_entry_id = item.get("testset_entry_id")
        artifact_id = item.get("artifact_id")
        if testset_entry_id is None or artifact_id is None:
            row = self.conn.execute(
                """SELECT t.id AS testset_entry_id,a.id AS artifact_id
                   FROM target_mappings m JOIN testset_entries t ON t.id=m.testset_entry_id
                   JOIN target_artifacts a ON a.id=m.artifact_id JOIN build_variants v ON v.id=a.build_variant_id
                   WHERE t.cve_id=? AND t.label=? AND t.tag=? AND t.binary_name=?
                     AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=?""",
                (item["cve_id"], item.get("label", ""), item["tag"], item["binary_name"], architecture, item.get("compiler", ""), item.get("opt", ""), item.get("build_profile", "")),
            ).fetchone()
            if row:
                testset_entry_id = row["testset_entry_id"]
                artifact_id = row["artifact_id"]
        if testset_entry_id is None or artifact_id is None:
            raise ValueError(f"review has no target mapping: {item['cve_id']} {item.get('tag','')}")
        report = item.get("report", {})
        policy = report.get("policy") if isinstance(report, dict) else None
        policy = policy or item.get("policy") or "affectedness-audit-v1"
        self.conn.execute(
            """INSERT INTO affectedness_reviews(testset_entry_id,reviewed_artifact_id,policy,architecture,status,confidence,reason,evidence_json,
                   suggested_action,missing_functions_json,report_json,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
               ON CONFLICT(testset_entry_id,policy,architecture) DO UPDATE SET
                 reviewed_artifact_id=excluded.reviewed_artifact_id,
                 status=excluded.status,confidence=excluded.confidence,reason=excluded.reason,
                 evidence_json=excluded.evidence_json,suggested_action=excluded.suggested_action,
                 missing_functions_json=excluded.missing_functions_json,report_json=excluded.report_json,
                 updated_at=CURRENT_TIMESTAMP
               WHERE affectedness_reviews.status='failed'""",
            (testset_entry_id, artifact_id, policy, architecture, item.get("status", "inconclusive"), item.get("confidence", 0.0), item.get("reason", ""),
             json.dumps(item.get("evidence", []), ensure_ascii=False), item.get("suggested_action", ""),
             json.dumps(item.get("missing_functions", []), ensure_ascii=False), json.dumps(report, ensure_ascii=False)),
        )
        self.conn.commit()
