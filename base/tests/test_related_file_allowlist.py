from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from RCA.related_file_allowlist import (
    ALLOWLIST_SCHEMA,
    DEFAULT_MAX_FILES,
    build_project_allowlist,
    merge_project_allowlist,
    select_file_records,
)


class RelatedFileAllowlistTest(unittest.TestCase):
    cve_id = "CVE-2024-4242"

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "tests@example.invalid")
        self.git("config", "user.name", "Dataset Tests")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def git(self, *args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(self.repo), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return proc.stdout.strip()

    def write(self, path: str, text: str) -> None:
        output = self.repo / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def build_fixture(self) -> tuple[str, str, Path, dict, dict]:
        self.write(
            "patch.c",
            """#include \"types.h\"\n#include \"macros.h\"\n#include \"unused.h\"\n\nint helper(struct config *cfg);\n\nint target(struct config *cfg)\n{\n    return helper(cfg);\n}\n""",
        )
        self.write("types.h", "struct config { int value; };\n")
        self.write("macros.h", "#define LIMIT 7\n")
        self.write("unused.h", "#define UNUSED_VALUE 1\n")
        self.write(
            "helper.c",
            "#include \"types.h\"\nint helper(struct config *cfg) { static int calls; calls++; return cfg->value; }\n",
        )
        self.write("other.c", "static int helper(struct config *cfg) { return cfg->value + 1; }\n")
        self.write("unrelated/helper.c", "int helper(struct config *cfg) { return cfg->value + 2; }\n")
        self.write("caller.c", "#include \"types.h\"\nint target(struct config *cfg);\nint caller(struct config *cfg) { return target(cfg); }\n")
        self.write("notes.txt", "old\n")
        parent = self.commit("base")

        self.write(
            "patch.c",
            """#include \"types.h\"\n#include \"macros.h\"\n#include \"unused.h\"\n\nint helper(struct config *cfg);\n\nint target(struct config *cfg)\n{\n    if (cfg->value > LIMIT)\n        return helper(cfg);\n    return 0;\n}\n""",
        )
        self.write("notes.txt", "new\n")
        commit = self.commit("fix")
        diff_path = self.root / "fix.diff"
        diff_path.write_text(self.git("diff", f"{parent}..{commit}"), encoding="utf-8")
        changed_lines = [
            index
            for index, line in enumerate((self.repo / "patch.c").read_text(encoding="utf-8").splitlines(), start=1)
            if "LIMIT" in line or "helper(cfg)" in line
        ]
        input_cves = {
            self.cve_id: {
                "functions": ["target"],
                "diff_related": [{"file": str(diff_path)}],
                "function_code": {"commit": commit, "by_function": {"target": {"file": "patch.c"}}},
            }
        }
        full_cves = {
            self.cve_id: {
                "function_analyses": [
                    {
                        "function": {"name": "target", "file": "patch.c", "commit": commit},
                        "patch": {"diff_file": str(diff_path)},
                        "step_b": {
                            "called_apis": ["helper"],
                            "macros": [{"name": "LIMIT"}],
                            "changed_lines": [{"line": line} for line in changed_lines],
                        },
                    }
                ]
            }
        }
        return parent, commit, diff_path, input_cves, full_cves

    def test_expands_callee_type_and_macro_without_caller_or_include_closure(self) -> None:
        _, _, _, input_cves, full_cves = self.build_fixture()
        output = build_project_allowlist("demo", self.repo, input_cves, full_cves)
        item = output["cves"][self.cve_id]
        related_files = {entry["path"]: entry for entry in item["related_files"]}

        self.assertEqual(output["schema"], ALLOWLIST_SCHEMA)
        self.assertEqual(item["seed_files"], ["patch.c"])
        self.assertEqual(item["patch_functions"], [{"name": "target", "file": "patch.c"}])
        self.assertEqual(set(related_files), {"helper.c", "types.h", "macros.h"})
        self.assertNotIn("caller.c", related_files)
        self.assertNotIn("unused.h", related_files)
        self.assertNotIn("other.c", related_files)
        self.assertNotIn("unrelated/helper.c", related_files)
        self.assertEqual(related_files["helper.c"]["functions"], ["helper"])
        self.assertEqual(related_files["types.h"]["types"], ["config"])
        self.assertEqual(related_files["macros.h"]["macros"], ["LIMIT"])
        self.assertNotIn("unresolved_symbols", item)
        self.assertNotIn("score", related_files["helper.c"])

    def test_caps_related_files_at_the_budget(self) -> None:
        records = [{"path": "patch.c", "score": 1000}]
        records.extend({"path": f"helpers/{index}.c", "score": 300} for index in range(DEFAULT_MAX_FILES + 2))
        selected, truncated = select_file_records(records, ["patch.c"])
        self.assertEqual(len(selected), DEFAULT_MAX_FILES)
        self.assertTrue(truncated)
        self.assertEqual(selected[0]["path"], "patch.c")

    def test_keeps_all_patch_seed_files_when_they_exceed_the_budget(self) -> None:
        parent, _, _, _, _ = self.build_fixture()
        for index in range(DEFAULT_MAX_FILES + 1):
            self.write(f"seed_{index}.c", f"int seed_{index}(void) {{ return {index}; }}\n")
        commit = self.commit("many seed files")
        diff_path = self.root / "seeds.diff"
        diff_path.write_text(self.git("diff", f"{parent}..{commit}"), encoding="utf-8")
        input_cves = {
            self.cve_id: {
                "diff_related": [{"file": str(diff_path)}],
                "function_code": {"commit": commit, "by_function": {}},
            }
        }
        output = build_project_allowlist("demo", self.repo, input_cves, {self.cve_id: {}})
        item = output["cves"][self.cve_id]
        self.assertGreater(len(item["seed_files"]), DEFAULT_MAX_FILES)
        self.assertEqual(item["related_files"], [])
        self.assertTrue(item["truncated"])

    def test_scoped_updates_merge_without_losing_existing_cves(self) -> None:
        original = {
            "schema": ALLOWLIST_SCHEMA,
            "project": "demo",
            "cves": {"CVE-2024-0001": {}},
        }
        updates = {
            "schema": ALLOWLIST_SCHEMA,
            "project": "demo",
            "cves": {self.cve_id: {}},
        }
        merged = merge_project_allowlist(original, updates)
        self.assertEqual(set(merged["cves"]), {"CVE-2024-0001", self.cve_id})

    def test_parser_failure_still_retains_patch_seed(self) -> None:
        _, _, _, input_cves, full_cves = self.build_fixture()
        broken_parser = SimpleNamespace(parse=mock.Mock(side_effect=RuntimeError("parser unavailable")))
        with mock.patch("RCA.related_file_allowlist.C_PARSER", broken_parser):
            output = build_project_allowlist("demo", self.repo, input_cves, full_cves)

        item = output["cves"][self.cve_id]
        self.assertEqual(item["seed_files"], ["patch.c"])
        self.assertNotIn("unresolved_symbols", item)
        self.assertNotIn("analysis_status", item)

    def test_source_analysis_cli_writes_cumulative_allowlist(self) -> None:
        _, _, _, input_cves, _ = self.build_fixture()
        input_path = self.root / "input.json"
        full_path = self.root / "RCA" / "full.json"
        min_path = self.root / "RCA" / "min.json"
        allowlist_path = self.root / "RCA" / "allowlist.json"
        input_path.write_text(json.dumps(input_cves), encoding="utf-8")
        allowlist_path.parent.mkdir(parents=True, exist_ok=True)
        allowlist_path.write_text(
            json.dumps(
                {
                    "schema": ALLOWLIST_SCHEMA,
                    "project": "demo",
                    "cves": {"CVE-2024-0001": {}},
                }
            ),
            encoding="utf-8",
        )
        project_root = Path(__file__).resolve().parents[2]
        subprocess.run(
            [
                sys.executable,
                str(project_root / "base" / "RCA" / "project_source_analysis.py"),
                "--input",
                str(input_path),
                "--project",
                "demo",
                "--repo-path",
                str(self.repo),
                "--output-full",
                str(full_path),
                "--output-min",
                str(min_path),
                "--output-allowlist",
                str(allowlist_path),
            ],
            cwd=project_root,
            check=True,
        )
        written = json.loads(allowlist_path.read_text(encoding="utf-8"))
        self.assertEqual(written["schema"], ALLOWLIST_SCHEMA)
        self.assertEqual(set(written["cves"]), {"CVE-2024-0001", self.cve_id})


if __name__ == "__main__":
    unittest.main()
