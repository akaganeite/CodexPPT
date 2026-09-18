from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from deployed.candidate_discovery.metadata_backfill import backfill_project


class MetadataBackfillTests(unittest.TestCase):
    def test_backfill_limits_to_deployed_cves_and_recovers_source_coordinates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "src").mkdir()
            source = repo / "src" / "demo.c"
            source.write_text("int target(int x) { return x; }\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-m", "before"], check=True, stdout=subprocess.DEVNULL)
            source.write_text("int target(int x) { return x + 1; }\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "commit", "-am", "fix"], check=True, stdout=subprocess.DEVNULL)
            commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

            base = root / "datasets"
            diff_dir = base / "demo" / "Diff" / "demo" / "diff_files"
            diff_dir.mkdir(parents=True)
            diff = diff_dir / f"demo_CVE-2024-0001_{commit[:12]}.diff"
            diff.write_text(subprocess.check_output(["git", "-C", str(repo), "diff", "HEAD^", "HEAD"], text=True), encoding="utf-8")

            output = base / "deployed" / "demo"
            exports = output / "exports"
            state = output / "deployed" / "state"
            exports.mkdir(parents=True)
            state.mkdir(parents=True)
            (exports / "groundtruth.ubuntu-amd64.json").write_text(
                json.dumps([{"CVE": "CVE-2024-0001", "functions": ["target"], "vuln": [], "patch": []}]),
                encoding="utf-8",
            )
            (state / "metadata_rows.json").write_text(
                json.dumps(
                    [
                        {
                            "cve_id": "CVE-2024-0001",
                            "functions": ["target"],
                            "summary": "demo",
                            "source_evidence": {"commit": commit, "by_function": {"target": {"file": ""}}},
                            "diff_evidence": [{"file": f"/old/mount/{diff.name}"}],
                            "raw": {"cwe": ["CWE-787"]},
                        },
                        {"cve_id": "CVE-2024-9999", "functions": ["ignored"]},
                    ]
                ),
                encoding="utf-8",
            )

            stats = backfill_project(
                project="demo", output=output, repo=repo, base_root=base, arch="amd64"
            )
            metadata = json.loads((exports / "demo_metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(list(metadata), ["CVE-2024-0001"])
            self.assertEqual(metadata["CVE-2024-0001"]["function_code"]["by_function"]["target"]["file"], "src/demo.c")
            self.assertEqual(metadata["CVE-2024-0001"]["diff_related"][0]["file"], str(diff))
            self.assertEqual(len(metadata["CVE-2024-0001"]["diff_related"][0]["related_hunks"]), 1)
            self.assertEqual(stats["unresolved_functions"], [])


if __name__ == "__main__":
    unittest.main()
