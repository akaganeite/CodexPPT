from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 4
LEGACY_TABLES = (
    "fix_candidates",
    "source_functions",
    "rca_statuses",
    "reference_binaries",
    "reference_binaries_v2",
    "target_binaries",
    "target_artifacts",
    "target_mappings",
    "target_mappings_v2",
    "not_affected_reports",
    "not_affected_reviews",
    "testset_entries",
)

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  detail_json TEXT,
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT
);
CREATE TABLE IF NOT EXISTS project (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cves (
  cve_id TEXT PRIMARY KEY,
  raw_json TEXT NOT NULL,
  summary TEXT,
  cwe_json TEXT,
  references_json TEXT,
  published TEXT,
  last_modified TEXT,
  selected INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'raw'
);
CREATE TABLE IF NOT EXISTS fix_candidates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  commit_hash TEXT NOT NULL,
  parent_hash TEXT,
  relation TEXT,
  confidence REAL,
  evidence_json TEXT,
  source TEXT,
  selected INTEGER NOT NULL DEFAULT 0,
  diff_path TEXT,
  patch_id TEXT,
  status TEXT NOT NULL DEFAULT 'candidate',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(cve_id, commit_hash),
  FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS source_functions (
  cve_id TEXT NOT NULL,
  commit_hash TEXT NOT NULL,
  function TEXT NOT NULL,
  change_type TEXT,
  file_path TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(cve_id, commit_hash, function),
  FOREIGN KEY(cve_id, commit_hash) REFERENCES fix_candidates(cve_id, commit_hash) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS releases (
  tag TEXT PRIMARY KEY,
  commit_sha TEXT,
  date TEXT,
  version TEXT,
  norm_tag TEXT
);
CREATE TABLE IF NOT EXISTS build_variants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  architecture TEXT NOT NULL DEFAULT 'x86_64',
  compiler TEXT NOT NULL,
  opt TEXT NOT NULL,
  build_profile TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(architecture, compiler, opt, build_profile)
);
CREATE TABLE IF NOT EXISTS reference_binaries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  build_variant_id INTEGER NOT NULL,
  vuln_commit TEXT,
  patch_commit TEXT,
  binary_name TEXT,
  vuln_path TEXT,
  patch_path TEXT,
  functions_json TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  report_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(cve_id, build_variant_id),
  FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
  FOREIGN KEY(build_variant_id) REFERENCES build_variants(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS testset_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  label TEXT NOT NULL,
  version TEXT NOT NULL,
  tag TEXT NOT NULL,
  binary_name TEXT NOT NULL,
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'selected',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(cve_id, label, tag, binary_name),
  FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
  FOREIGN KEY(tag) REFERENCES releases(tag) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS target_artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT NOT NULL,
  version TEXT NOT NULL,
  binary_name TEXT NOT NULL,
  build_variant_id INTEGER NOT NULL,
  path TEXT,
  debug_path TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  report_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(tag, binary_name, build_variant_id),
  FOREIGN KEY(tag) REFERENCES releases(tag) ON DELETE RESTRICT,
  FOREIGN KEY(build_variant_id) REFERENCES build_variants(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS target_mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  testset_entry_id INTEGER NOT NULL,
  artifact_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  report_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(testset_entry_id, artifact_id),
  FOREIGN KEY(testset_entry_id) REFERENCES testset_entries(id) ON DELETE CASCADE,
  FOREIGN KEY(artifact_id) REFERENCES target_artifacts(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS affectedness_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  testset_entry_id INTEGER NOT NULL,
  reviewed_artifact_id INTEGER,
  policy TEXT NOT NULL,
  architecture TEXT NOT NULL DEFAULT 'x86_64',
  status TEXT NOT NULL,
  confidence REAL,
  reason TEXT,
  evidence_json TEXT,
  suggested_action TEXT,
  missing_functions_json TEXT NOT NULL DEFAULT '[]',
  report_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(testset_entry_id, policy, architecture),
  FOREIGN KEY(testset_entry_id) REFERENCES testset_entries(id) ON DELETE CASCADE,
  FOREIGN KEY(reviewed_artifact_id) REFERENCES target_artifacts(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS stage_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stage TEXT NOT NULL,
  status TEXT NOT NULL,
  detail_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_stage_runs_stage_id ON stage_runs(stage, id DESC);
CREATE INDEX IF NOT EXISTS idx_build_variants_identity
  ON build_variants(architecture, compiler, opt, build_profile);
CREATE INDEX IF NOT EXISTS idx_affectedness_reviews_identity
  ON affectedness_reviews(testset_entry_id, policy, architecture);
CREATE TABLE IF NOT EXISTS rca_statuses (
  cve_id TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  artifact_path TEXT,
  detail_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(cve_id, mode),
  FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);
"""


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def execute_schema(conn: sqlite3.Connection, include_journal_mode: bool = True) -> None:
    statement = ""
    for line in SCHEMA.splitlines():
        if not include_journal_mode and line.strip().upper().startswith("PRAGMA JOURNAL_MODE"):
            continue
        statement += line + "\n"
        if sqlite3.complete_statement(statement):
            conn.execute(statement)
            statement = ""
    if statement.strip():
        raise RuntimeError("incomplete SQLite schema statement")


def create_backup(path: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = path.with_name(f"{path.name}.pre-schema-v{SCHEMA_VERSION}-{stamp}.bak")
    source = sqlite3.connect(str(path))
    backup = sqlite3.connect(str(backup_path))
    try:
        source.backup(backup)
    finally:
        backup.close()
        source.close()
    return backup_path


def stored_output(conn: sqlite3.Connection, fallback: Path) -> Path:
    if not table_exists(conn, "project"):
        return fallback
    row = conn.execute("SELECT value FROM project WHERE key='build_config'").fetchone()
    if not row:
        return fallback
    try:
        value = json.loads(row[0])
    except (TypeError, json.JSONDecodeError):
        return fallback
    output = value.get("output") if isinstance(value, dict) else None
    return Path(output) if output else fallback


def portable_path(value: str | None, old_output: Path, new_output: Path) -> str:
    if not value:
        return ""
    path = Path(value)
    if not path.is_absolute():
        return str(path)
    for root in (old_output, new_output):
        try:
            return str(path.relative_to(root))
        except ValueError:
            try:
                return str(path.resolve().relative_to(root.resolve()))
            except ValueError:
                continue
    return str(path)


def normalize_managed_paths(conn: sqlite3.Connection, db_path: Path) -> dict[str, int]:
    output = db_path.parent
    updates = {
        "fix_candidates.diff_path": 0,
        "reference_binaries.vuln_path": 0,
        "reference_binaries.patch_path": 0,
        "target_artifacts.path": 0,
        "target_artifacts.debug_path": 0,
        "rca_statuses.artifact_path": 0,
    }
    for table, column, keys in (
        ("fix_candidates", "diff_path", ("id",)),
        ("reference_binaries", "vuln_path", ("id",)),
        ("reference_binaries", "patch_path", ("id",)),
        ("target_artifacts", "path", ("id",)),
        ("target_artifacts", "debug_path", ("id",)),
        ("rca_statuses", "artifact_path", ("cve_id", "mode")),
    ):
        if not table_exists(conn, table):
            continue
        selected = ",".join((*keys, column))
        for row in conn.execute(f"SELECT {selected} FROM {table} WHERE COALESCE({column},'')!=''").fetchall():
            normalized = portable_path(row[column], output, output)
            if normalized == row[column]:
                continue
            predicate = " AND ".join(f"{key}=?" for key in keys)
            conn.execute(f"UPDATE {table} SET {column}=? WHERE {predicate}", (normalized, *(row[key] for key in keys)))
            updates[f"{table}.{column}"] += 1
    conn.commit()
    return updates


def policy_from_report(report_json: str | None) -> str:
    try:
        report = json.loads(report_json or "{}")
    except json.JSONDecodeError:
        report = {}
    policy = report.get("policy") if isinstance(report, dict) else None
    return str(policy or "legacy-not-affected-v0")


def ensure_variant(
    conn: sqlite3.Connection,
    compiler: str,
    opt: str,
    build_profile: str,
    architecture: str = "x86_64",
) -> int:
    conn.execute(
        "INSERT OR IGNORE INTO build_variants(architecture,compiler,opt,build_profile) VALUES(?,?,?,?)",
        (architecture or "x86_64", compiler or "", opt or "", build_profile or ""),
    )
    return conn.execute(
        "SELECT id FROM build_variants WHERE architecture=? AND compiler=? AND opt=? AND build_profile=?",
        (architecture or "x86_64", compiler or "", opt or "", build_profile or ""),
    ).fetchone()[0]


def migrate_reviews_v2_to_v3(conn: sqlite3.Connection) -> dict[str, Any]:
    if not table_exists(conn, "affectedness_reviews"):
        execute_schema(conn, include_journal_mode=False)
        return {"affectedness_reviews": 0, "review_conflicts": []}
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(affectedness_reviews)")}
    if "testset_entry_id" in columns:
        return {"affectedness_reviews": conn.execute("SELECT COUNT(*) FROM affectedness_reviews").fetchone()[0], "review_conflicts": []}

    rows = conn.execute(
        """
        SELECT r.*,m.testset_entry_id,m.artifact_id
        FROM affectedness_reviews r
        JOIN target_mappings m ON m.id=r.target_mapping_id
        ORDER BY r.updated_at,r.id
        """
    ).fetchall()
    grouped: dict[tuple[int, str], list[sqlite3.Row]] = {}
    for row in rows:
        grouped.setdefault((row["testset_entry_id"], row["policy"]), []).append(row)
    conflicts = []
    chosen = []
    for (testset_entry_id, policy), candidates in grouped.items():
        statuses = {row["status"] for row in candidates}
        if len(statuses) > 1:
            entry = conn.execute(
                "SELECT cve_id,label,tag,binary_name FROM testset_entries WHERE id=?",
                (testset_entry_id,),
            ).fetchone()
            conflicts.append(
                {
                    "testset_entry_id": testset_entry_id,
                    "policy": policy,
                    "statuses": sorted(statuses),
                    **(dict(entry) if entry else {}),
                }
            )
            continue
        chosen.append(candidates[-1])

    conn.execute("ALTER TABLE affectedness_reviews RENAME TO affectedness_reviews_v2")
    conn.execute(
        """
        CREATE TABLE affectedness_reviews (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          testset_entry_id INTEGER NOT NULL,
          reviewed_artifact_id INTEGER,
          policy TEXT NOT NULL,
          status TEXT NOT NULL,
          confidence REAL,
          reason TEXT,
          evidence_json TEXT,
          suggested_action TEXT,
          missing_functions_json TEXT NOT NULL DEFAULT '[]',
          report_json TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(testset_entry_id, policy),
          FOREIGN KEY(testset_entry_id) REFERENCES testset_entries(id) ON DELETE CASCADE,
          FOREIGN KEY(reviewed_artifact_id) REFERENCES target_artifacts(id) ON DELETE SET NULL
        )
        """
    )
    for row in chosen:
        conn.execute(
            """
            INSERT INTO affectedness_reviews(
              testset_entry_id,reviewed_artifact_id,policy,status,confidence,reason,evidence_json,
              suggested_action,missing_functions_json,report_json,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                row["testset_entry_id"], row["artifact_id"], row["policy"], row["status"], row["confidence"],
                row["reason"], row["evidence_json"], row["suggested_action"], row["missing_functions_json"],
                row["report_json"], row["created_at"], row["updated_at"],
            ),
        )
    conn.execute("DROP TABLE affectedness_reviews_v2")
    return {
        "affectedness_reviews": len(chosen),
        "reviews_deduplicated": len(rows) - len(chosen) - sum(len(grouped[(item["testset_entry_id"], item["policy"])]) for item in conflicts),
        "review_conflicts": conflicts,
    }


def migrate_v2_to_v3(conn: sqlite3.Connection) -> dict[str, Any]:
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("BEGIN IMMEDIATE")
    try:
        stats = migrate_reviews_v2_to_v3(conn)
        conn.execute("PRAGMA user_version=3")
        conn.execute(
            "INSERT OR REPLACE INTO schema_migrations(version,name,status,detail_json,completed_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)",
            (3, "global-affectedness-reviews", "ok", json.dumps(stats, ensure_ascii=False)),
        )
        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"foreign key violations after v3 migration: {violations[:10]}")
        conn.commit()
        return stats
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")


def migrate_v3_to_v4(conn: sqlite3.Connection) -> dict[str, Any]:
    """Split x86 and AArch64 build/review identities without disturbing child IDs."""
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("PRAGMA legacy_alter_table=ON")
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("ALTER TABLE build_variants RENAME TO build_variants_v3")
        conn.execute(
            """
            CREATE TABLE build_variants (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              architecture TEXT NOT NULL DEFAULT 'x86_64',
              compiler TEXT NOT NULL,
              opt TEXT NOT NULL,
              build_profile TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(architecture, compiler, opt, build_profile)
            )
            """
        )
        variants = conn.execute("SELECT * FROM build_variants_v3 ORDER BY id").fetchall()
        conn.executemany(
            """
            INSERT INTO build_variants(id,architecture,compiler,opt,build_profile,created_at)
            VALUES(?,?,?,?,?,?)
            """,
            [
                (
                    row["id"],
                    "x86_64",
                    row["compiler"],
                    row["opt"],
                    row["build_profile"],
                    row["created_at"],
                )
                for row in variants
            ],
        )
        conn.execute("DROP TABLE build_variants_v3")

        reviews = []
        if table_exists(conn, "affectedness_reviews"):
            conn.execute("ALTER TABLE affectedness_reviews RENAME TO affectedness_reviews_v3")
            reviews = conn.execute("SELECT * FROM affectedness_reviews_v3 ORDER BY id").fetchall()
        conn.execute(
            """
            CREATE TABLE affectedness_reviews (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              testset_entry_id INTEGER NOT NULL,
              reviewed_artifact_id INTEGER,
              policy TEXT NOT NULL,
              architecture TEXT NOT NULL DEFAULT 'x86_64',
              status TEXT NOT NULL,
              confidence REAL,
              reason TEXT,
              evidence_json TEXT,
              suggested_action TEXT,
              missing_functions_json TEXT NOT NULL DEFAULT '[]',
              report_json TEXT,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(testset_entry_id, policy, architecture),
              FOREIGN KEY(testset_entry_id) REFERENCES testset_entries(id) ON DELETE CASCADE,
              FOREIGN KEY(reviewed_artifact_id) REFERENCES target_artifacts(id) ON DELETE SET NULL
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO affectedness_reviews(
              id,testset_entry_id,reviewed_artifact_id,policy,architecture,status,confidence,reason,evidence_json,
              suggested_action,missing_functions_json,report_json,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            [
                (
                    row["id"],
                    row["testset_entry_id"],
                    row["reviewed_artifact_id"],
                    row["policy"],
                    "x86_64",
                    row["status"],
                    row["confidence"],
                    row["reason"],
                    row["evidence_json"],
                    row["suggested_action"],
                    row["missing_functions_json"],
                    row["report_json"],
                    row["created_at"],
                    row["updated_at"],
                )
                for row in reviews
            ],
        )
        conn.execute("DROP TABLE IF EXISTS affectedness_reviews_v3")
        execute_schema(conn, include_journal_mode=False)
        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"foreign key violations after v4 migration: {violations[:10]}")
        stats = {"build_variants": len(variants), "affectedness_reviews": len(reviews), "architecture": "x86_64"}
        conn.execute("PRAGMA user_version=4")
        conn.execute(
            "INSERT OR REPLACE INTO schema_migrations(version,name,status,detail_json,completed_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)",
            (4, "architecture-isolated-builds", "ok", json.dumps(stats, ensure_ascii=False)),
        )
        conn.commit()
        return stats
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA legacy_alter_table=OFF")
        conn.execute("PRAGMA foreign_keys=ON")


def migrate_legacy(conn: sqlite3.Connection, db_path: Path) -> dict[str, Any]:
    old_output = stored_output(conn, db_path.parent)
    new_output = db_path.parent
    existing = {table for table in LEGACY_TABLES if table_exists(conn, table)}
    if not existing:
        execute_schema(conn)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        conn.execute(
            "INSERT OR REPLACE INTO schema_migrations(version,name,status,detail_json,completed_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)",
            (SCHEMA_VERSION, "normalized-build-storage", "ok", json.dumps({"fresh": True})),
        )
        conn.commit()
        return {"fresh": True}

    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("BEGIN IMMEDIATE")
    try:
        for table in existing:
            conn.execute(f'ALTER TABLE "{table}" RENAME TO "legacy_{table}"')
        execute_schema(conn, include_journal_mode=False)
        stats: dict[str, Any] = {"fresh": False, "old_output": str(old_output), "new_output": str(new_output)}
        fix_rows = conn.execute("SELECT * FROM legacy_fix_candidates ORDER BY id").fetchall() if table_exists(conn, "legacy_fix_candidates") else []
        for row in fix_rows:
            conn.execute(
                """INSERT INTO fix_candidates(
                     id,cve_id,commit_hash,parent_hash,relation,confidence,evidence_json,source,selected,
                     diff_path,patch_id,status,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (row["id"], row["cve_id"], row["commit_hash"], row["parent_hash"], row["relation"], row["confidence"],
                 row["evidence_json"], row["source"], row["selected"], portable_path(row["diff_path"], old_output, new_output),
                 row["patch_id"], row["status"], row["created_at"]),
            )
        function_rows = conn.execute("SELECT * FROM legacy_source_functions").fetchall() if table_exists(conn, "legacy_source_functions") else []
        for row in function_rows:
            conn.execute(
                "INSERT INTO source_functions(cve_id,commit_hash,function,change_type,file_path,active) VALUES(?,?,?,?,?,?)",
                (row["cve_id"], row["commit_hash"], row["function"], row["change_type"], row["file_path"], row["active"]),
            )
        rca_rows = conn.execute("SELECT * FROM legacy_rca_statuses").fetchall() if table_exists(conn, "legacy_rca_statuses") else []
        for row in rca_rows:
            conn.execute(
                """INSERT INTO rca_statuses(cve_id,mode,status,artifact_path,detail_json,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (row["cve_id"], row["mode"], row["status"], portable_path(row["artifact_path"], old_output, new_output),
                 row["detail_json"], row["created_at"], row["updated_at"]),
            )
        stats["fix_candidates"] = len(fix_rows)
        stats["source_functions"] = len(function_rows)
        stats["rca_statuses"] = len(rca_rows)
        stats["diff_paths_normalized"] = sum(bool(row["diff_path"]) for row in fix_rows)
        stats["rca_paths_normalized"] = sum(bool(row["artifact_path"]) for row in rca_rows)

        legacy_testset = "legacy_testset_entries"
        if table_exists(conn, legacy_testset):
            rows = conn.execute(f"SELECT * FROM {legacy_testset} ORDER BY cve_id,label,tag,binary_name").fetchall()
            for row in rows:
                conn.execute(
                    """INSERT INTO testset_entries(cve_id,label,version,tag,binary_name,reason,status)
                       VALUES(?,?,?,?,?,?,?)
                       ON CONFLICT(cve_id,label,tag,binary_name) DO UPDATE SET
                         version=excluded.version,reason=excluded.reason,status=excluded.status,updated_at=CURRENT_TIMESTAMP""",
                    (row["cve_id"], row["label"], row["version"], row["tag"], row["binary_name"] or "", row["reason"], row["status"]),
                )
            stats["testset_entries"] = len(rows)

        ref_source = "legacy_reference_binaries_v2" if table_exists(conn, "legacy_reference_binaries_v2") else "legacy_reference_binaries"
        if table_exists(conn, ref_source):
            rows = conn.execute(f"SELECT * FROM {ref_source}").fetchall()
            for row in rows:
                keys = row.keys()
                variant_id = ensure_variant(conn, row["compiler"] if "compiler" in keys else "", row["opt"] if "opt" in keys else "", row["build_profile"] if "build_profile" in keys else "")
                conn.execute(
                    """INSERT INTO reference_binaries(
                         cve_id,build_variant_id,vuln_commit,patch_commit,binary_name,vuln_path,patch_path,
                         functions_json,status,report_json,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,COALESCE(?,CURRENT_TIMESTAMP),COALESCE(?,CURRENT_TIMESTAMP))
                       ON CONFLICT(cve_id,build_variant_id) DO UPDATE SET
                         vuln_commit=excluded.vuln_commit,patch_commit=excluded.patch_commit,
                         binary_name=excluded.binary_name,vuln_path=excluded.vuln_path,patch_path=excluded.patch_path,
                         functions_json=excluded.functions_json,status=excluded.status,report_json=excluded.report_json,
                         updated_at=excluded.updated_at""",
                    (row["cve_id"], variant_id, row["vuln_commit"], row["patch_commit"], row["binary_name"], portable_path(row["vuln_path"], old_output, new_output), portable_path(row["patch_path"], old_output, new_output), row["functions_json"], row["status"], row["report_json"], row["created_at"] if "created_at" in keys else None, row["updated_at"] if "updated_at" in keys else None),
                )
            stats["reference_binaries"] = len(rows)

        artifact_ids: dict[int, int] = {}
        if table_exists(conn, "legacy_target_artifacts"):
            rows = conn.execute("SELECT * FROM legacy_target_artifacts ORDER BY id").fetchall()
            for row in rows:
                variant_id = ensure_variant(conn, row["compiler"], row["opt"], row["build_profile"])
                report = {}
                try:
                    report = json.loads(row["report_json"] or "{}")
                except json.JSONDecodeError:
                    pass
                debug_path = ""
                if isinstance(report, dict):
                    split = report.get("debug_split")
                    if isinstance(split, dict):
                        debug_path = portable_path(split.get("debug_path"), old_output, new_output)
                conn.execute(
                    """INSERT INTO target_artifacts(tag,version,binary_name,build_variant_id,path,debug_path,status,report_json,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(tag,binary_name,build_variant_id) DO UPDATE SET
                         version=excluded.version,path=excluded.path,debug_path=excluded.debug_path,status=excluded.status,
                         report_json=excluded.report_json,updated_at=excluded.updated_at""",
                    (row["tag"], row["version"], row["binary_name"], variant_id, portable_path(row["path"], old_output, new_output), debug_path, row["status"], row["report_json"], row["created_at"], row["updated_at"]),
                )
                new_id = conn.execute("SELECT id FROM target_artifacts WHERE tag=? AND binary_name=? AND build_variant_id=?", (row["tag"], row["binary_name"], variant_id)).fetchone()[0]
                artifact_ids[row["id"]] = new_id
            stats["target_artifacts"] = len(rows)

        mapping_ids: dict[tuple[str, str, str, str, str, str, str], int] = {}
        stale_mappings = 0
        if table_exists(conn, "legacy_target_mappings_v2"):
            rows = conn.execute("SELECT * FROM legacy_target_mappings_v2 ORDER BY updated_at,rowid").fetchall()
            for row in rows:
                testset = conn.execute("SELECT id FROM testset_entries WHERE cve_id=? AND label=? AND tag=? AND binary_name=?", (row["cve_id"], row["label"], row["tag"], row["binary_name"])).fetchone()
                artifact_id = artifact_ids.get(row["artifact_id"])
                if not testset or not artifact_id:
                    stale_mappings += 1
                    continue
                conn.execute(
                    """INSERT INTO target_mappings(testset_entry_id,artifact_id,status,report_json,created_at,updated_at)
                       VALUES(?,?,?,?,?,?) ON CONFLICT(testset_entry_id,artifact_id) DO UPDATE SET
                         status=excluded.status,report_json=excluded.report_json,updated_at=excluded.updated_at""",
                    (testset[0], artifact_id, row["status"], row["report_json"], row["created_at"], row["updated_at"]),
                )
                mapping_id = conn.execute("SELECT id FROM target_mappings WHERE testset_entry_id=? AND artifact_id=?", (testset[0], artifact_id)).fetchone()[0]
                mapping_ids[(row["cve_id"], row["label"], row["tag"], row["binary_name"], row["compiler"], row["opt"], row["build_profile"])] = mapping_id
            stats["target_mappings"] = conn.execute("SELECT COUNT(*) FROM target_mappings").fetchone()[0]
            stats["stale_mappings_pruned"] = stale_mappings

        review_rows = []
        if table_exists(conn, "legacy_not_affected_reviews"):
            review_rows = conn.execute("SELECT * FROM legacy_not_affected_reviews ORDER BY updated_at,id").fetchall()
            grouped: dict[tuple[int, str], list[tuple[sqlite3.Row, int]]] = {}
            stale_reviews = 0
            for row in review_rows:
                key = (row["cve_id"], row["label"], row["tag"], row["binary_name"], row["compiler"], row["opt"], row["build_profile"])
                mapping_id = mapping_ids.get(key)
                if not mapping_id:
                    stale_reviews += 1
                    continue
                mapping = conn.execute("SELECT testset_entry_id,artifact_id FROM target_mappings WHERE id=?", (mapping_id,)).fetchone()
                grouped.setdefault((mapping["testset_entry_id"], policy_from_report(row["report_json"])), []).append((row, mapping["artifact_id"]))
            chosen: list[tuple[int, str, sqlite3.Row, int]] = []
            conflicts = []
            for (testset_entry_id, policy), candidates in grouped.items():
                statuses = {row["status"] for row, _ in candidates}
                if len(statuses) > 1:
                    entry = conn.execute("SELECT cve_id,label,tag,binary_name FROM testset_entries WHERE id=?", (testset_entry_id,)).fetchone()
                    conflicts.append({"testset_entry_id": testset_entry_id, "policy": policy, "statuses": sorted(statuses), **dict(entry)})
                    continue
                row, artifact_id = candidates[-1]
                chosen.append((testset_entry_id, policy, row, artifact_id))
            for testset_entry_id, policy, row, artifact_id in chosen:
                conn.execute(
                    """INSERT INTO affectedness_reviews(
                         testset_entry_id,reviewed_artifact_id,policy,status,confidence,reason,evidence_json,suggested_action,
                         missing_functions_json,report_json,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (testset_entry_id, artifact_id, policy, row["status"], row["confidence"], row["reason"], row["evidence_json"], row["suggested_action"], row["missing_functions_json"] or "[]", row["report_json"], row["created_at"], row["updated_at"]),
                )
            stats["affectedness_reviews"] = len(chosen)
            stats["reviews_deduplicated"] = len(review_rows) - stale_reviews - len(chosen) - sum(len(grouped[(item["testset_entry_id"], item["policy"])]) for item in conflicts)
            stats["stale_reviews_pruned"] = stale_reviews
            stats["review_conflicts"] = conflicts

        for table in existing:
            conn.execute(f'DROP TABLE IF EXISTS "legacy_{table}"')
        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"foreign key violations after migration: {violations[:10]}")
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        conn.execute(
            "INSERT OR REPLACE INTO schema_migrations(version,name,status,detail_json,completed_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)",
            (SCHEMA_VERSION, "normalized-build-storage", "ok", json.dumps(stats, ensure_ascii=False)),
        )
        conn.commit()
        return stats
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")


def initialize_database(conn: sqlite3.Connection, db_path: Path) -> dict[str, Any]:
    conn.row_factory = sqlite3.Row
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError(f"database schema version {version} is newer than supported version {SCHEMA_VERSION}")
    if version < SCHEMA_VERSION:
        backup_path = create_backup(db_path) if db_path.exists() and db_path.stat().st_size else None
        if version == 3:
            result = migrate_v3_to_v4(conn)
        elif version == 2:
            migrate_v2_to_v3(conn)
            result = migrate_v3_to_v4(conn)
        else:
            result = migrate_legacy(conn, db_path)
        if backup_path is not None:
            result["backup_path"] = str(backup_path)
            conn.execute(
                "UPDATE schema_migrations SET detail_json=? WHERE version=?",
                (json.dumps(result, ensure_ascii=False), SCHEMA_VERSION),
            )
            conn.commit()
        conn.execute("PRAGMA foreign_keys=ON")
        return result
    execute_schema(conn)
    conn.execute("PRAGMA foreign_keys=ON")
    normalize_managed_paths(conn, db_path)
    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(f"foreign key violations: {violations[:10]}")
    conn.commit()
    return {"version": version}
