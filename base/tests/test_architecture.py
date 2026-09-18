from __future__ import annotations

import shutil
import sqlite3
import subprocess
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

from binarybuild.debug_split import run_debug_split
from binarybuild.target_build import map_built_binary
from builder import cli
from builder.architecture import (
    elf_architecture,
    matches_elf_architecture,
    normalize_architecture,
    resolve_toolchain,
    validate_toolchain,
)
from builder.db import ProjectDB
from binarybuild.not_affected_review import POLICY
from test_support import DatabaseTestCase, add_artifact, add_testset, make_config, write_elf
from testset.export_stage import export_outputs, export_variant_testset_and_groundtruth


class ArchitectureConfigTest(DatabaseTestCase):
    def test_elf_architecture_reads_only_the_header(self) -> None:
        class RecordingStream(BytesIO):
            read_sizes: list[int]

            def __init__(self, payload: bytes) -> None:
                super().__init__(payload)
                self.read_sizes = []

            def read(self, size: int = -1) -> bytes:
                self.read_sizes.append(size)
                return super().read(size)

        header = bytearray(20)
        header[:4] = b"\x7fELF"
        header[5] = 1
        header[18:20] = (0x3E).to_bytes(2, "little")
        stream = RecordingStream(bytes(header) + b"unused payload")

        with patch.object(Path, "open", return_value=stream):
            self.assertEqual(elf_architecture(Path("unused")), "x86_64")

        self.assertEqual(stream.read_sizes, [20])

    def test_cli_normalizes_arm64_and_preserves_x86_default_names(self) -> None:
        parser = cli.build_parser()
        arm = parser.parse_args(
            [
                "build",
                "-p",
                "demo",
                "--repo",
                str(self.root / "repo"),
                "--output",
                str(self.root / "out"),
                "--cve",
                "CVE-2024-0001",
                "--arch",
                "arm64",
            ]
        )
        x86 = parser.parse_args(
            [
                "build",
                "-p",
                "demo",
                "--repo",
                str(self.root / "repo"),
                "--output",
                str(self.root / "out"),
                "--cve",
                "CVE-2024-0001",
            ]
        )
        self.assertEqual(arm.arch, "aarch64")
        self.assertEqual(x86.arch, "x86_64")
        self.assertEqual(normalize_architecture("amd64"), "x86_64")

        arm_config = make_config(self.root, [], "gcc", "-O2", "arm64")
        x86_config = make_config(self.root, [], "gcc", "-O2")
        self.assertEqual(arm_config.build_variant, "aarch64-gcc-O2")
        self.assertEqual(x86_config.build_variant, "gcc-O2")
        self.assertEqual(arm_config.reference_bin_dir, self.root / "binaries" / "reference" / "demo" / "aarch64")
        self.assertEqual(x86_config.reference_bin_dir, self.root / "binaries" / "reference" / "demo")

    def test_aarch64_toolchain_contract_and_missing_cxx_diagnostic(self) -> None:
        gcc = resolve_toolchain("aarch64", "gcc")
        clang = resolve_toolchain("aarch64", "clang")
        self.assertEqual(gcc.c_compiler, "aarch64-linux-gnu-gcc")
        self.assertEqual(gcc.configure_host, "aarch64-linux-gnu")
        self.assertEqual(clang.compiler_flags, ("--target=aarch64-linux-gnu", "--gcc-toolchain=/usr"))

        with patch(
            "builder.architecture.which",
            side_effect=lambda command: None if command == "aarch64-linux-gnu-g++" else "/usr/bin/tool",
        ):
            with self.assertRaisesRegex(ValueError, r"g\+\+-aarch64-linux-gnu"):
                validate_toolchain("aarch64", "gcc")


class ArchitecturePersistenceTest(DatabaseTestCase):
    def _downgrade_to_v3(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("PRAGMA legacy_alter_table=ON")
        conn.execute("BEGIN")
        conn.execute("ALTER TABLE build_variants RENAME TO build_variants_v4")
        conn.execute(
            """
            CREATE TABLE build_variants (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              compiler TEXT NOT NULL,
              opt TEXT NOT NULL,
              build_profile TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(compiler, opt, build_profile)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO build_variants(id,compiler,opt,build_profile,created_at)
            SELECT id,compiler,opt,build_profile,created_at FROM build_variants_v4
            """
        )
        conn.execute("DROP TABLE build_variants_v4")
        conn.execute("ALTER TABLE affectedness_reviews RENAME TO affectedness_reviews_v4")
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
        conn.execute(
            """
            INSERT INTO affectedness_reviews(
              id,testset_entry_id,reviewed_artifact_id,policy,status,confidence,reason,evidence_json,
              suggested_action,missing_functions_json,report_json,created_at,updated_at
            )
            SELECT id,testset_entry_id,reviewed_artifact_id,policy,status,confidence,reason,evidence_json,
                   suggested_action,missing_functions_json,report_json,created_at,updated_at
            FROM affectedness_reviews_v4
            """
        )
        conn.execute("DROP TABLE affectedness_reviews_v4")
        conn.execute("DELETE FROM schema_migrations WHERE version=4")
        conn.execute("PRAGMA user_version=3")
        conn.commit()
        conn.close()

    def test_v3_migration_marks_existing_state_as_x86_64(self) -> None:
        db = self.open_db("v3.sqlite")
        cve_id = "CVE-2024-8100"
        add_testset(db, cve_id, "v1")
        artifact_id = add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2")
        vuln, patch = self.root / "ref-v", self.root / "ref-p"
        write_elf(vuln)
        write_elf(patch)
        db.upsert_reference(
            {
                "cve_id": cve_id,
                "compiler": "gcc",
                "opt": "-O0",
                "vuln_path": vuln,
                "patch_path": patch,
                "status": "ok",
            }
        )
        candidate = db.selected_target_candidates(make_config(self.root, [cve_id], "gcc", "-O2"))[0]
        db.upsert_not_affected_review({**candidate, "status": "affected", "report": {"policy": POLICY}})
        self.close_db(db)
        path = self.root / "v3.sqlite"
        self._downgrade_to_v3(path)

        migrated = self.open_db("v3.sqlite")
        self.assertEqual(migrated.conn.execute("PRAGMA user_version").fetchone()[0], 4)
        self.assertEqual(
            migrated.conn.execute("SELECT architecture FROM build_variants WHERE id=(SELECT build_variant_id FROM target_artifacts WHERE id=?)", (artifact_id,)).fetchone()[0],
            "x86_64",
        )
        self.assertEqual(migrated.conn.execute("SELECT architecture FROM affectedness_reviews").fetchone()[0], "x86_64")
        self.assertIsNotNone(migrated.reference_for_cve(cve_id, make_config(self.root, [cve_id], "gcc", "-O2")))
        self.assertIsNotNone(migrated.target_mapping_for_testset(migrated.testset_entries()[0], make_config(self.root, [cve_id], "gcc", "-O2")))
        self.assertFalse(migrated.conn.execute("PRAGMA foreign_key_check").fetchall())

    def test_artifacts_and_reviews_are_architecture_isolated(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-8101"
        add_testset(db, cve_id, "v1")
        add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2")
        add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2", architecture="aarch64")
        x86_config = make_config(self.root, [cve_id], "gcc", "-O2")
        arm_config = make_config(self.root, [cve_id], "gcc", "-O2", "aarch64")
        x86_candidate = db.selected_target_candidates(x86_config)[0]
        arm_candidate = db.selected_target_candidates(arm_config)[0]
        db.upsert_not_affected_review({**x86_candidate, "status": "affected", "report": {"policy": POLICY}})
        self.assertEqual(len(db.pending_not_affected_candidates(arm_config, POLICY)), 1)
        db.upsert_not_affected_review({**arm_candidate, "status": "not_affected", "report": {"policy": POLICY}})
        rows = list(db.conn.execute("SELECT architecture,status FROM affectedness_reviews ORDER BY architecture"))
        self.assertEqual([(row["architecture"], row["status"]) for row in rows], [("aarch64", "not_affected"), ("x86_64", "affected")])

    def test_wrong_architecture_target_is_not_mapped(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-8102"
        add_testset(db, cve_id, "v1")
        config = make_config(self.root, [cve_id], "gcc", "-O2", "aarch64")
        wrong = self.root / "wrong-x86"
        write_elf(wrong, "x86_64")
        row = db.testset_entries(config)[0]
        ok = map_built_binary(db, config, dict(row), str(wrong), [dict(row)], Mock(), source="test")
        self.assertFalse(ok)
        self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM target_artifacts").fetchone()[0], 0)

    def test_reference_resume_rejects_wrong_architecture_elf(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-8104"
        commit = "a" * 40
        add_testset(db, cve_id, "v1")
        db.upsert_fix_candidate(cve_id, {"commit": commit, "parent": "b" * 40, "selected": True})
        db.replace_source_functions(cve_id, commit, [{"function": "demo_function", "file": "demo.c"}])
        vuln, patch = self.root / "wrong-ref-vuln", self.root / "wrong-ref-patch"
        write_elf(vuln, "x86_64")
        write_elf(patch, "x86_64")
        db.upsert_reference(
            {
                "cve_id": cve_id,
                "compiler": "gcc",
                "opt": "-O0",
                "architecture": "aarch64",
                "vuln_path": vuln,
                "patch_path": patch,
                "status": "ok",
            }
        )
        config = make_config(self.root, [cve_id], "gcc", "-O2", "aarch64")
        db.record_stage("reference_build", "ok")
        self.assertEqual(db.selected_fixes_missing_reference(config), [cve_id])
        self.assertFalse(db.stage_satisfied("reference_build", config))

    def test_reference_resume_rejects_missing_required_symbols(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-8105"
        commit = "c" * 40
        add_testset(db, cve_id, "v1")
        db.upsert_fix_candidate(cve_id, {"commit": commit, "parent": "d" * 40, "selected": True})
        db.replace_source_functions(cve_id, commit, [{"function": "required_function", "file": "demo.c"}])
        vuln, patch = self.root / "arm-ref-vuln", self.root / "arm-ref-patch"
        write_elf(vuln, "aarch64")
        write_elf(patch, "aarch64")
        db.upsert_reference(
            {
                "cve_id": cve_id,
                "compiler": "gcc",
                "opt": "-O0",
                "architecture": "aarch64",
                "vuln_path": vuln,
                "patch_path": patch,
                "functions": ["required_function"],
                "status": "ok",
            }
        )
        config = make_config(self.root, [cve_id], "gcc", "-O2", "aarch64")
        db.record_stage("reference_build", "ok")
        self.assertEqual(db.selected_fixes_missing_reference(config), [cve_id])
        self.assertFalse(db.stage_satisfied("reference_build", config))

    def test_aarch64_variant_exports_do_not_create_canonical_x86_files(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-8103"
        add_testset(db, cve_id, "v1")
        add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2", architecture="aarch64")
        config = make_config(self.root, [cve_id], "gcc", "-O2", "aarch64")
        export_variant_testset_and_groundtruth(config, db)
        export_outputs(config, db)
        exports = self.root / "exports"
        self.assertTrue((exports / "testset.aarch64-gcc-O2.json").is_file())
        self.assertTrue((exports / "groundtruth.aarch64-gcc-O2.json").is_file())
        self.assertTrue((exports / "demo_reference.aarch64.json").is_file())
        self.assertFalse((exports / "testset.json").exists())
        self.assertFalse((exports / "groundtruth.json").exists())

    def test_export_resume_checks_are_architecture_specific(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-8106"
        add_testset(db, cve_id, "v1")
        add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2")
        add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2", architecture="aarch64")
        x86_config = make_config(self.root, [cve_id], "gcc", "-O2")
        arm_config = make_config(self.root, [cve_id], "gcc", "-O2", "aarch64")

        export_variant_testset_and_groundtruth(arm_config, db)
        export_outputs(arm_config, db)
        self.assertFalse(db.stage_satisfied("variant_export", x86_config))
        self.assertFalse(db.stage_satisfied("export", x86_config))

        export_variant_testset_and_groundtruth(x86_config, db)
        export_outputs(x86_config, db)
        self.assertTrue(db.stage_satisfied("variant_export", x86_config))
        self.assertTrue(db.stage_satisfied("export", x86_config))


class AArch64IntegrationTest(DatabaseTestCase):
    @unittest.skipUnless(
        all(shutil.which(command) for command in ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-objcopy", "aarch64-linux-gnu-strip")),
        "AArch64 GNU compiler/binutils are not installed",
    )
    def test_cross_compiled_target_survives_mapping_and_debug_split(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-8105"
        add_testset(db, cve_id, "v1")
        config = make_config(self.root, [cve_id], "gcc", "-O0", "aarch64")
        source = self.root / "minimal.c"
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        target = self.root / "minimal-aarch64"
        subprocess.run(["aarch64-linux-gnu-gcc", "-g", "-O0", "-o", str(target), str(source)], check=True)
        self.assertEqual(elf_architecture(target), "aarch64")

        row = dict(db.testset_entries(config)[0])
        self.assertTrue(map_built_binary(db, config, row, str(target), [row], Mock(), source="cross-test"))
        raw = config.target_bin_dir / config.target_binary_name(row["version"], row["binary_name"])
        self.assertTrue(matches_elf_architecture(raw, "aarch64"))

        run_debug_split(config, db)

        rows = db.variant_export_rows(config)
        self.assertEqual(len(rows), 1)
        self.assertTrue(matches_elf_architecture(Path(rows[0]["path"]), "aarch64"))
        self.assertTrue(matches_elf_architecture(Path(rows[0]["debug_path"]), "aarch64"))


if __name__ == "__main__":
    unittest.main()
