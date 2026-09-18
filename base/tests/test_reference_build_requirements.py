from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from binarybuild.reference_build import (
    choose_pair_binary,
    cleanup_unreferenced_reference_files,
    profile_order_for_task,
    reference_function_requirements,
)
from builder.config import BuildConfig


class RequirementDB:
    def functions_for_cve(self, cve_id: str, include_added: bool = True):
        return ["added_fn", "deleted_fn", "modified_fn"]

    def function_details_for_cve(self, cve_id: str):
        return [
            {"function": "added_fn", "change_type": "added"},
            {"function": "deleted_fn", "change_type": "deleted"},
            {"function": "modified_fn", "change_type": "modified"},
        ]


class PairCompiler:
    def __init__(self, missing_patch: list[str] | None = None) -> None:
        self.missing_patch = missing_patch or []
        self.choose_calls: list[tuple[str, ...]] = []

    def compile_commit(self, config, commit, stage, log, profile="shared"):
        return SimpleNamespace(ok=True, commit=commit, worktree=Path(f"/{commit}"), notes="")

    def choose_binary(self, worktree, functions, preferred="", profile="shared"):
        self.choose_calls.append(tuple(functions))
        missing = self.missing_patch if str(worktree) == "/patch" else []
        return SimpleNamespace(path=Path(worktree) / "tool", binary_name="tool", missing=missing)


class ReferenceBuildRequirementTests(unittest.TestCase):
    def config(self, root: Path) -> BuildConfig:
        return BuildConfig(
            project="demo",
            repo=root / "repo",
            output=root / "output",
            db_path=root / "output" / "demo.sqlite",
            vendor_product="demo:demo",
            latest=0,
            cves=[],
            compiler="gcc",
            opt="-O0",
            codex_model="",
            codex_sandbox="danger-full-access",
            batch_size=10,
            github_token="",
            nvd_api_key="",
            metadata_mode="skip",
            resume=True,
            cleanup_worktrees="success",
            cleanup_build_logs="success",
            testset_count=3,
            testset_strategy="chronical",
        )

    def test_functions_are_required_only_on_sides_where_they_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            diff = Path(tmp) / "fix.diff"
            diff.write_text("", encoding="utf-8")
            row = {"cve_id": "CVE-2024-1000", "diff_path": str(diff)}
            functions, patch_functions, vuln_functions = reference_function_requirements(RequirementDB(), row)
        self.assertEqual(functions, ["added_fn", "deleted_fn", "modified_fn"])
        self.assertEqual(patch_functions, ["added_fn", "modified_fn"])
        self.assertEqual(vuln_functions, ["deleted_fn", "modified_fn"])

    def test_pair_selection_rejects_a_patch_missing_required_functions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self.config(Path(tmp))
            task = {
                "functions": ["added_fn", "modified_fn"],
                "patch_functions": ["added_fn", "modified_fn"],
                "vuln_functions": ["modified_fn"],
                "patch_commit": "patch",
                "vuln_commit": "vuln",
            }
            compiler = PairCompiler(missing_patch=["added_fn"])
            vuln, patch, _, notes, _ = choose_pair_binary(config, compiler, task, "shared", SimpleNamespace())
        self.assertIsNone(vuln)
        self.assertIsNone(patch)
        self.assertIn("added_fn", notes[0])

    def test_reference_requirements_ignore_test_only_hunk_functions(self) -> None:
        class DB:
            def functions_for_cve(self, cve_id: str, include_added: bool = True):
                return ["product_fn", "test"]

            def function_details_for_cve(self, cve_id: str):
                return [
                    {"function": "product_fn", "change_type": "modified"},
                    {"function": "test", "change_type": "modified"},
                ]

        with tempfile.TemporaryDirectory() as tmp:
            diff = Path(tmp) / "fix.diff"
            diff.write_text(
                """diff --git a/lib/product.c b/lib/product.c
--- a/lib/product.c
+++ b/lib/product.c
@@ -1,2 +1,2 @@ int product_fn(void)
diff --git a/tests/libtest/case.c b/tests/libtest/case.c
--- a/tests/libtest/case.c
+++ b/tests/libtest/case.c
@@ -1,2 +1,2 @@ int test(char *URL)
""",
                encoding="utf-8",
            )
            row = {"cve_id": "CVE-2024-1001", "diff_path": str(diff)}
            functions, patch_functions, vuln_functions = reference_function_requirements(DB(), row)
        self.assertEqual(functions, ["product_fn"])
        self.assertEqual(patch_functions, ["product_fn"])
        self.assertEqual(vuln_functions, ["product_fn"])

    def test_active_source_functions_override_extra_diff_hunks(self) -> None:
        class DB:
            def functions_for_cve(self, cve_id: str, include_added: bool = True):
                return ["security_path"]

            def function_details_for_cve(self, cve_id: str):
                return [{"function": "security_path", "change_type": "modified"}]

        with tempfile.TemporaryDirectory() as tmp:
            diff = Path(tmp) / "fix.diff"
            diff.write_text(
                "@@ -1,2 +1,2 @@ int security_path(void)\n"
                "@@ -3,2 +3,2 @@ int unrelated_backend(void)\n",
                encoding="utf-8",
            )
            row = {"cve_id": "CVE-2024-1002", "diff_path": str(diff)}
            functions, _, _ = reference_function_requirements(DB(), row)
        self.assertEqual(functions, ["security_path"])

    def test_pair_selection_does_not_require_added_function_on_vuln_side(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self.config(Path(tmp))
            task = {
                "functions": ["added_fn", "modified_fn"],
                "patch_functions": ["added_fn", "modified_fn"],
                "vuln_functions": ["modified_fn"],
                "patch_commit": "patch",
                "vuln_commit": "vuln",
            }
            compiler = PairCompiler()
            vuln, patch, binary_name, notes, _ = choose_pair_binary(
                config, compiler, task, "shared", SimpleNamespace()
            )
        self.assertIsNotNone(vuln)
        self.assertIsNotNone(patch)
        self.assertEqual(binary_name, "tool")
        self.assertEqual(notes, [])
        self.assertEqual(compiler.choose_calls, [("added_fn", "modified_fn"), ("modified_fn",)])

    def test_component_specific_profiles_are_selected_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diff = root / "fix.diff"
            diff.write_text("", encoding="utf-8")
            ffmpeg = self.config(root)
            ffmpeg.project = "ffmpeg"
            sqlite = self.config(root)
            sqlite.project = "sqlite"
            binutils = self.config(root)
            binutils.project = "binutils"
            openssl = self.config(root)
            openssl.project = "openssl"
            curl = self.config(root)
            curl.project = "curl"
            self.assertEqual(
                profile_order_for_task(binutils, {"diff_path": str(diff), "functions": ["scan"]}),
                ("static", "shared"),
            )
            self.assertEqual(
                profile_order_for_task(
                    ffmpeg,
                    {"diff_path": str(diff), "functions": ["cbs_jpeg_split_fragment"]},
                )[:2],
                ("shared-cbs-jpeg", "static-cbs-jpeg"),
            )
            self.assertEqual(
                profile_order_for_task(
                    ffmpeg,
                    {"diff_path": str(diff), "functions": ["dwa_uncompress"]},
                )[:2],
                ("shared-exr-zlib", "static-exr-zlib"),
            )
            self.assertEqual(
                profile_order_for_task(
                    sqlite,
                    {"diff_path": str(diff), "functions": ["vdbeVComment"]},
                )[:2],
                ("shared-explain-comments", "static-explain-comments"),
            )
            self.assertEqual(
                profile_order_for_task(
                    openssl,
                    {"diff_path": str(diff), "functions": ["tls13_process_compressed_certificate"]},
                )[:2],
                ("static-zlib", "shared-zlib"),
            )
            diff.write_text(
                "diff --git a/lib/vtls/mbedtls.c b/lib/vtls/mbedtls.c\n+++ b/lib/vtls/mbedtls.c\n",
                encoding="utf-8",
            )
            self.assertEqual(
                profile_order_for_task(
                    curl,
                    {"diff_path": str(diff), "functions": ["mbed_connect_step1", "polarssl_connect_step1"]},
                )[:2],
                ("shared-vtls-mbed-polar", "static-vtls-mbed-polar"),
            )
            diff.write_text(
                "diff --git a/src/tool_urlglob.c b/src/tool_urlglob.c\n+++ b/src/tool_urlglob.c\n",
                encoding="utf-8",
            )
            self.assertEqual(
                profile_order_for_task(curl, {"diff_path": str(diff), "functions": ["glob_range"]}),
                ("static", "shared"),
            )

    def test_reference_cleanup_removes_only_unreferenced_scoped_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.config(root)
            config.cves = ["CVE-2024-1000"]
            config.reference_bin_dir.mkdir(parents=True)
            keep = config.reference_bin_dir / "CVE-2024-1000-vuln-a-tool"
            orphan = config.reference_bin_dir / "CVE-2024-1000-vuln-old-tool"
            other = config.reference_bin_dir / "CVE-2024-2000-vuln-old-tool"
            for path in (keep, orphan, other):
                path.write_bytes(b"x")

            class DB:
                def references(self, scoped_config):
                    return [{"vuln_path": str(keep), "patch_path": str(keep)}]

            log = SimpleNamespace(trace=lambda *args, **kwargs: None)
            self.assertEqual(cleanup_unreferenced_reference_files(config, DB(), log), 1)
            self.assertTrue(keep.exists())
            self.assertFalse(orphan.exists())
            self.assertTrue(other.exists())


if __name__ == "__main__":
    unittest.main()
