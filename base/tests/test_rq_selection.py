from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from testset.rq_selection import select_rq2_rq3_testset


class RqSelectionTest(unittest.TestCase):
    def write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_excludes_patch_evolution_and_preserves_paired_labels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "dataset"
            exports = output / "exports"
            repo = root / "repo"
            repo.mkdir()
            diff_dir = output / "Diff" / "demo" / "diff_files"
            diff_dir.mkdir(parents=True)
            diffs = {}
            for cve_id, before, after in (
                ("CVE-2024-0001", "if (len == 0) return -1;", "if (len < 2) return -1;"),
                ("CVE-2024-0002", "foo();", "bar();"),
                ("CVE-2024-0003", "value = 0;", "value = 1;"),
            ):
                path = diff_dir / f"demo_{cve_id}.diff"
                path.write_text(
                    "diff --git a/src/a.c b/src/a.c\n"
                    "--- a/src/a.c\n"
                    "+++ b/src/a.c\n"
                    "@@ -1 +1 @@\n"
                    f"-{before}\n"
                    f"+{after}\n",
                    encoding="utf-8",
                )
                diffs[cve_id] = str(path)

            metadata = {
                cve_id: {
                    "functions": ["target"],
                    "cwe": ["CWE-119"],
                    "diff_related": [{"file": diff_path}],
                    "function_code": {"commit": "", "by_function": {"target": {"file": "src/a.c", "change_type": "modified"}}},
                }
                for cve_id, diff_path in diffs.items()
            }
            pick = [
                {"CVE": cve_id, "functions": ["target"], "binaries": [f"{cve_id}-vuln", f"{cve_id}-patch"]}
                for cve_id in metadata
            ]
            next(item for item in pick if item["CVE"] == "CVE-2024-0003")["binaries"] = ["CVE-2024-0003-not-affected"]
            groundtruth = [
                {
                    "CVE": cve_id,
                    "functions": ["target"],
                    "vuln": [f"{cve_id}-vuln"],
                    "patch": [f"{cve_id}-patch"],
                    "not_affected": [],
                }
                for cve_id in metadata
            ]
            next(item for item in groundtruth if item["CVE"] == "CVE-2024-0003")["not_affected"] = [
                "CVE-2024-0003-not-affected"
            ]
            reviews = [
                {"CVE": "CVE-2024-0001", "review": {"status": "affected", "reason": "target was compiled normally"}},
                {"CVE": "CVE-2024-0002", "review": {"status": "patch_evolution"}},
                {
                    "CVE": "CVE-2024-0003",
                    "review": {"status": "not_affected", "reason": "target binary does not link the optional demo backend"},
                },
            ]
            self.write_json(exports / "demo_metadata.json", metadata)
            self.write_json(exports / "testset.pick.json", pick)
            self.write_json(exports / "groundtruth_with_not_affected.json", groundtruth)
            self.write_json(exports / "not_affected_candidates.json", reviews)

            result = select_rq2_rq3_testset(project="demo", repo=repo, output=output, count=3)

            self.assertEqual(result["selected_count"], 2)
            selected = json.loads(Path(result["testset"]).read_text(encoding="utf-8"))
            self.assertEqual({item["CVE"] for item in selected}, {"CVE-2024-0001", "CVE-2024-0003"})
            conditional = next(item for item in selected if item["CVE"] == "CVE-2024-0003")
            self.assertIn("CVE-2024-0003-not-affected", conditional["binaries"])
            self.assertIn("CVE-2024-0003-vuln", conditional["binaries"])
            self.assertIn("CVE-2024-0003-patch", conditional["binaries"])
            selected_gt = json.loads(Path(result["groundtruth"]).read_text(encoding="utf-8"))
            self.assertTrue(all(len(item["vuln"]) == len(item["patch"]) == 1 for item in selected_gt))
            manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["excluded"]["patch_evolution"], ["CVE-2024-0002"])
            first = next(item for item in manifest["selected"] if item["cve_id"] == "CVE-2024-0001")
            self.assertNotIn("conditional_compilation", first["rq3_categories"])
            third = next(item for item in manifest["selected"] if item["cve_id"] == "CVE-2024-0003")
            self.assertIn("conditional_compilation", third["rq3_categories"])
            self.assertTrue(third["pick_repaired_after_review"])


if __name__ == "__main__":
    unittest.main()
