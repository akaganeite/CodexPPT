from __future__ import annotations

import json
from unittest.mock import Mock, patch

from binarybuild import not_affected_review
from binarybuild.affectedness_evidence import artifact_evidence, target_arch
from test_support import DatabaseTestCase, add_artifact, add_testset, make_config


class AffectednessReviewTest(DatabaseTestCase):
    def test_artifact_evidence_reports_elf_dependency_and_adapter_facts(self) -> None:
        target = self.root / "target"
        debug = self.root / "target.debug"
        header = bytearray(20)
        header[:4] = b"\x7fELF"
        header[4] = 2
        header[5] = 1
        header[18:20] = (0x3E).to_bytes(2, "little")
        target.write_bytes(header)
        debug.write_bytes(header)
        config = make_config(self.root, [], "gcc", "-O2")
        candidate = {
            "target_path": str(target),
            "debug_path": str(debug),
            "compiler": "gcc",
            "opt": "-O2",
            "build_profile": "",
            "artifact_report_json": json.dumps({"source": "local_target_build"}),
        }

        def command_output(command: list[str]) -> str:
            if command[0] == "file":
                return "ELF 64-bit LSB shared object"
            if command[:2] == ["readelf", "-dW"]:
                return " 0x0000000000000001 (NEEDED) Shared library: [libssl.so.3]\n"
            return ""

        with patch("binarybuild.affectedness_evidence.command_text", side_effect=command_output):
            evidence = artifact_evidence(config, candidate)

        self.assertEqual(target_arch(target), "elf64/x86-64")
        self.assertEqual(evidence["target"]["dynamic_dependencies"], ["libssl.so.3"])
        self.assertEqual(evidence["debug_companion"]["path"], str(debug))
        self.assertEqual(evidence["build"]["artifact_record"], {"source": "local_target_build"})

    def test_v2_review_is_preferred_while_v1_remains_export_fallback(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-7000"
        add_testset(db, cve_id, "v1")
        add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2")
        config = make_config(self.root, [cve_id], "gcc", "-O2")
        candidate = db.selected_target_candidates(config)[0]
        db.upsert_not_affected_review(
            {**candidate, "status": "not_affected", "report": {"policy": "affectedness-audit-v1"}}
        )

        self.assertEqual(len(db.pending_not_affected_candidates(config, policy=not_affected_review.POLICY)), 1)
        fallback = db.not_affected_review_for_candidate(
            candidate,
            policy=not_affected_review.POLICY,
            fallback_policies=not_affected_review.LEGACY_POLICIES,
        )
        self.assertEqual(fallback["policy"], "affectedness-audit-v1")

        db.upsert_not_affected_review(
            {**candidate, "status": "affected", "report": {"policy": not_affected_review.POLICY}}
        )
        preferred = db.not_affected_review_for_candidate(
            candidate,
            policy=not_affected_review.POLICY,
            fallback_policies=not_affected_review.LEGACY_POLICIES,
        )
        self.assertEqual(preferred["policy"], not_affected_review.POLICY)
        self.assertEqual(preferred["status"], "affected")
        self.assertEqual(db.pending_not_affected_candidates(config, policy=not_affected_review.POLICY), [])

    def test_default_review_routes_every_pending_candidate_to_codex(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-7001"
        add_testset(db, cve_id, "v1")
        add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2")
        config = make_config(self.root, [cve_id], "gcc", "-O2")

        with patch.object(not_affected_review, "run_not_affected_review_codex", return_value=[]) as codex:
            not_affected_review.run_not_affected_review(config, db)

        self.assertEqual(codex.call_count, 1)
        self.assertEqual(len(codex.call_args.args[2]), 1)
        self.assertEqual(
            db.conn.execute("SELECT COUNT(*) FROM affectedness_reviews WHERE policy=?", (not_affected_review.POLICY,)).fetchone()[0],
            0,
        )

    def test_prompt_requires_artifact_review_and_permits_read_only_tools(self) -> None:
        config = make_config(self.root, [], "gcc", "-O2")
        prompt = not_affected_review.render_prompt(
            config,
            [
                {
                    "target_path": "/tmp/target",
                    "debug_path": "/tmp/target.debug",
                    "tag": "v1",
                    "target_tag": "v1",
                    "target_commit": "commit",
                    "binary_name": "tool",
                    "compiler": "gcc",
                    "opt": "-O2",
                    "build_profile": "",
                    "artifact_evidence": {"target": {"architecture": "elf64/x86-64"}},
                    "candidates": [],
                }
            ],
        )
        self.assertIn("Audit the produced target artifact", prompt)
        self.assertIn("You may use file, readelf, nm, objdump, strings, ldd", prompt)
        self.assertIn("Do not use web search or network access", prompt)
        self.assertIn("Source history alone does not prove", prompt)

    def test_result_records_artifact_aware_protocol(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-7002"
        add_testset(db, cve_id, "v1")
        add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2")
        config = make_config(self.root, [cve_id], "gcc", "-O2")
        candidate = db.selected_target_candidates(config)[0]
        candidate["artifact_evidence"] = {"target": {"architecture": "elf64/x86-64"}}
        result = {
            "items": [
                {
                    "cve_id": cve_id,
                    "label": "vuln",
                    "tag": "v1",
                    "binary_name": "tool",
                    "compiler": "gcc",
                    "opt": "-O2",
                    "build_profile": "",
                    "target_path": candidate["target_path"],
                    "missing_functions": [],
                    "status": "not_affected",
                    "confidence": 0.9,
                    "reason": "binary platform excludes the path",
                    "evidence": ["target is x86-64"],
                    "suggested_action": "keep not_affected",
                }
            ]
        }

        failed = not_affected_review.record_review_results(db, Mock(), [candidate], result)
        self.assertEqual(failed, [])
        row = db.not_affected_review_for_candidate(candidate, policy=not_affected_review.POLICY)
        report = json.loads(row["report_json"])
        self.assertEqual(report["review_protocol"], "artifact-aware-direct-codex-v2")
        self.assertEqual(report["artifact_evidence"]["target"]["architecture"], "elf64/x86-64")
