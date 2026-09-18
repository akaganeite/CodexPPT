from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path

from builder.db import ProjectDB
from builder.db_schema import migrate_legacy
from test_support import DatabaseTestCase, add_artifact, add_testset, make_config


def create_legacy_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE project(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE cves(cve_id TEXT PRIMARY KEY,raw_json TEXT NOT NULL,summary TEXT,cwe_json TEXT,references_json TEXT,published TEXT,last_modified TEXT,selected INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'raw');
        CREATE TABLE fix_candidates(id INTEGER PRIMARY KEY AUTOINCREMENT,cve_id TEXT NOT NULL,commit_hash TEXT NOT NULL,parent_hash TEXT,relation TEXT,confidence REAL,evidence_json TEXT,source TEXT,selected INTEGER NOT NULL DEFAULT 0,diff_path TEXT,patch_id TEXT,status TEXT NOT NULL DEFAULT 'candidate',created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(cve_id,commit_hash));
        CREATE TABLE source_functions(cve_id TEXT NOT NULL,commit_hash TEXT NOT NULL,function TEXT NOT NULL,change_type TEXT,file_path TEXT,active INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(cve_id,commit_hash,function));
        CREATE TABLE releases(tag TEXT PRIMARY KEY,commit_sha TEXT,date TEXT,version TEXT,norm_tag TEXT);
        CREATE TABLE stage_runs(id INTEGER PRIMARY KEY AUTOINCREMENT,stage TEXT NOT NULL,status TEXT NOT NULL,detail_json TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE rca_statuses(cve_id TEXT NOT NULL,mode TEXT NOT NULL,status TEXT NOT NULL,artifact_path TEXT,detail_json TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(cve_id,mode));
        CREATE TABLE reference_binaries(cve_id TEXT PRIMARY KEY,vuln_commit TEXT,patch_commit TEXT,binary_name TEXT,vuln_path TEXT,patch_path TEXT,functions_json TEXT,status TEXT,report_json TEXT);
        CREATE TABLE reference_binaries_v2(cve_id TEXT NOT NULL,compiler TEXT NOT NULL,opt TEXT NOT NULL,build_profile TEXT NOT NULL,vuln_commit TEXT,patch_commit TEXT,binary_name TEXT,vuln_path TEXT,patch_path TEXT,functions_json TEXT,status TEXT,report_json TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(cve_id,compiler,opt,build_profile));
        CREATE TABLE testset_entries(cve_id TEXT NOT NULL,label TEXT NOT NULL,version TEXT NOT NULL,tag TEXT NOT NULL,binary_name TEXT,reason TEXT,status TEXT,PRIMARY KEY(cve_id,label,tag));
        CREATE TABLE target_binaries(cve_id TEXT,label TEXT,tag TEXT,binary_name TEXT,path TEXT,status TEXT,report_json TEXT,PRIMARY KEY(cve_id,label,tag,binary_name));
        CREATE TABLE target_artifacts(id INTEGER PRIMARY KEY AUTOINCREMENT,project TEXT,tag TEXT,version TEXT,binary_name TEXT,compiler TEXT,opt TEXT,build_profile TEXT,path TEXT,status TEXT,report_json TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(project,tag,binary_name,compiler,opt,build_profile));
        CREATE TABLE target_mappings(cve_id TEXT,label TEXT,tag TEXT,binary_name TEXT,artifact_id INTEGER,status TEXT,report_json TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(cve_id,label,tag,binary_name));
        CREATE TABLE target_mappings_v2(cve_id TEXT,label TEXT,tag TEXT,binary_name TEXT,compiler TEXT,opt TEXT,build_profile TEXT,artifact_id INTEGER,status TEXT,report_json TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(cve_id,label,tag,binary_name,compiler,opt,build_profile));
        CREATE TABLE not_affected_reports(id INTEGER PRIMARY KEY AUTOINCREMENT,cve_id TEXT,label TEXT,tag TEXT,binary_name TEXT,compiler TEXT,opt TEXT,build_profile TEXT,missing_functions_json TEXT,target_path TEXT,reason TEXT,report_json TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE not_affected_reviews(id INTEGER PRIMARY KEY AUTOINCREMENT,cve_id TEXT,label TEXT,tag TEXT,binary_name TEXT,compiler TEXT,opt TEXT,build_profile TEXT,missing_functions_json TEXT,target_path TEXT,status TEXT,confidence REAL,reason TEXT,evidence_json TEXT,suggested_action TEXT,report_json TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(cve_id,label,tag,binary_name,compiler,opt,build_profile,missing_functions_json));
        """
    )
    output = path.parent
    conn.execute("INSERT INTO project VALUES('build_config',?)", (json.dumps({"output": str(output), "compiler": "gcc", "opt": "-O0"}),))
    conn.execute("INSERT INTO cves VALUES('CVE-2024-0001','{}','summary','[]','[]','','',1,'ready')")
    conn.execute("INSERT INTO fix_candidates(cve_id,commit_hash,selected) VALUES('CVE-2024-0001','abc',1)")
    conn.execute("INSERT INTO source_functions VALUES('CVE-2024-0001','abc','func','modified','a.c',1)")
    conn.execute("INSERT INTO releases VALUES('v1','sha','','1','1')")
    conn.execute("INSERT INTO reference_binaries_v2(cve_id,compiler,opt,build_profile,vuln_path,patch_path,status) VALUES('CVE-2024-0001','gcc','-O0','',?,?, 'ok')", (str(output / 'ref-v'), str(output / 'ref-p')))
    conn.execute("INSERT INTO testset_entries VALUES('CVE-2024-0001','vuln','1','v1','tool','selected','selected')")
    conn.execute("INSERT INTO target_artifacts(project,tag,version,binary_name,compiler,opt,build_profile,path,status) VALUES('demo','v1','1','tool','gcc','-O0','',?,'ok')", (str(output / 'target'),))
    artifact_id = conn.execute("SELECT id FROM target_artifacts").fetchone()[0]
    conn.execute("INSERT INTO target_mappings_v2(cve_id,label,tag,binary_name,compiler,opt,build_profile,artifact_id,status) VALUES('CVE-2024-0001','vuln','v1','tool','gcc','-O0','',?,'ok')", (artifact_id,))
    for missing, status, updated in [('[]', 'affected', '2026-01-01'), ('["old"]', 'not_affected', '2026-02-01')]:
        conn.execute("INSERT INTO not_affected_reviews(cve_id,label,tag,binary_name,compiler,opt,build_profile,missing_functions_json,status,report_json,updated_at) VALUES('CVE-2024-0001','vuln','v1','tool','gcc','-O0','',?,?,?,?)", (missing, status, json.dumps({'policy': 'affectedness-audit-v1'}), updated))
    conn.commit()
    conn.close()


class DatabaseMigrationTest(DatabaseTestCase):
    def test_legacy_database_migrates_to_normalized_schema(self) -> None:
        path = self.root / "demo.sqlite"
        create_legacy_db(path)
        db = self.open_db()
        self.assertEqual(db.conn.execute("PRAGMA user_version").fetchone()[0], 4)
        self.assertEqual(db.conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertFalse(list(db.conn.execute("PRAGMA foreign_key_check")))
        self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM affectedness_reviews").fetchone()[0], 0)
        migration = json.loads(db.conn.execute("SELECT detail_json FROM schema_migrations WHERE version=4").fetchone()[0])
        self.assertEqual(len(migration["review_conflicts"]), 1)
        tables = {row[0] for row in db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("target_mappings_v2", tables)
        self.assertNotIn("not_affected_reviews", tables)
        self.assertEqual(db.conn.execute("SELECT path FROM target_artifacts").fetchone()[0], "target")
        self.close_db(db)
        ProjectDB(path).close()
        self.assertEqual(len(list(self.root.glob("demo.sqlite.pre-schema-v4-*.bak"))), 1)

    def test_failed_migration_rolls_back_legacy_tables(self) -> None:
        path = self.root / "broken.sqlite"
        create_legacy_db(path)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("DELETE FROM releases WHERE tag='v1'")
        conn.commit()
        with self.assertRaises(RuntimeError):
            migrate_legacy(conn, path)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("target_artifacts", tables)
        self.assertIn("target_mappings_v2", tables)
        self.assertNotIn("legacy_target_artifacts", tables)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 0)
        conn.close()

    def test_v2_reviews_merge_consistent_and_drop_conflicts(self) -> None:
        db = self.open_db()
        add_testset(db, "CVE-2024-2000", "v1")
        add_testset(db, "CVE-2024-2001", "v2")
        consistent_a = add_artifact(db, self.root, "CVE-2024-2000", "v1", "gcc", "-O2")
        consistent_b = add_artifact(db, self.root, "CVE-2024-2000", "v1", "clang", "-O3")
        conflict_a = add_artifact(db, self.root, "CVE-2024-2001", "v2", "gcc", "-O2")
        conflict_b = add_artifact(db, self.root, "CVE-2024-2001", "v2", "clang", "-O3")
        mappings = {row["artifact_id"]: row["id"] for row in db.conn.execute("SELECT id,artifact_id FROM target_mappings")}
        db.conn.execute("DROP TABLE affectedness_reviews")
        db.conn.execute(
            """CREATE TABLE affectedness_reviews(
                id INTEGER PRIMARY KEY AUTOINCREMENT,target_mapping_id INTEGER NOT NULL,policy TEXT NOT NULL,
                status TEXT NOT NULL,confidence REAL,reason TEXT,evidence_json TEXT,suggested_action TEXT,
                missing_functions_json TEXT NOT NULL DEFAULT '[]',report_json TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(target_mapping_id,policy))"""
        )
        rows = (
            (mappings[consistent_a], "affected"),
            (mappings[consistent_b], "affected"),
            (mappings[conflict_a], "affected"),
            (mappings[conflict_b], "not_affected"),
        )
        db.conn.executemany(
            "INSERT INTO affectedness_reviews(target_mapping_id,policy,status) VALUES(?,'affectedness-audit-v1',?)", rows
        )
        db.conn.execute("PRAGMA user_version=2")
        db.conn.commit()
        self.close_db(db)

        migrated = self.open_db()
        reviews = list(migrated.conn.execute("SELECT * FROM affectedness_reviews"))
        self.assertEqual([(row["status"], row["reviewed_artifact_id"]) for row in reviews], [("affected", consistent_b)])
        detail = json.loads(migrated.conn.execute("SELECT detail_json FROM schema_migrations WHERE version=3").fetchone()[0])
        self.assertEqual(len(detail["review_conflicts"]), 1)
        self.assertEqual(detail["review_conflicts"][0]["cve_id"], "CVE-2024-2001")
        config = make_config(self.root, ["CVE-2024-2001"], "clang", "-O3")
        self.assertEqual(len(migrated.pending_not_affected_candidates(config)), 1)
        self.assertEqual(migrated.conn.execute("PRAGMA foreign_key_check").fetchall(), [])


class NormalizedDatabaseCrudTest(DatabaseTestCase):
    def test_target_review_uses_normalized_keys_and_cascades(self) -> None:
        db = self.open_db("fresh.sqlite")
        add_testset(db, "CVE-2024-0002", "v2")
        artifact_id = add_artifact(db, self.root, "CVE-2024-0002", "v2", "gcc", "-O2")
        candidate = db.selected_target_candidates(make_config(self.root, [], "gcc", "-O2"))[0]
        db.upsert_not_affected_review({**candidate, "status": "affected", "report": {"policy": "affectedness-audit-v1"}})
        db.upsert_not_affected_review(
            {**candidate, "status": "not_affected", "missing_functions": ["legacy"], "report": {"policy": "affectedness-audit-v1"}}
        )
        self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM affectedness_reviews").fetchone()[0], 1)
        self.assertEqual(db.not_affected_review_for_candidate(candidate, "affectedness-audit-v1")["status"], "affected")
        db.replace_testset_entries("CVE-2024-0002", [])
        self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM target_mappings").fetchone()[0], 0)
        self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM affectedness_reviews").fetchone()[0], 0)
        self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM target_artifacts").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
