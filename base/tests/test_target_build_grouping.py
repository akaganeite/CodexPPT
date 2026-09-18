from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from binarybuild.target_build import profile_order_for_task_group, run_target_build_local
from builder.config import BuildConfig


class FakeDB:
    def target_artifact_for_task(self, *args, **kwargs):
        return None


class FakeOpenSSLCompiler:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.compile_calls: list[tuple[str, str]] = []
        self.copy_calls: list[Path] = []

    def compile_commit(self, config, tag, stage, log, profile="static"):
        self.compile_calls.append((tag, profile))
        worktree = self.root / f"worktree-{profile}"
        worktree.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(ok=True, worktree=worktree, notes="")

    def find_binary_by_name(self, worktree, binary_name, profile="static"):
        path = Path(worktree) / binary_name
        path.write_bytes(b"source")
        return path

    def copy_binary(self, source, destination):
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(Path(source).read_bytes())
        self.copy_calls.append(destination)


class TargetBuildGroupingTests(unittest.TestCase):
    def test_curl_gnutls_binary_uses_only_gnutls_profiles(self) -> None:
        config = SimpleNamespace(project="curl")
        tasks = [{"binary_name": "libcurl-gnutls", "version": "7.34"}]
        self.assertEqual(profile_order_for_task_group(config, tasks), ("shared-gnutls", "static-gnutls"))

    def test_old_openssl_executable_prefers_shared_profile(self) -> None:
        config = SimpleNamespace(project="openssl")
        tasks = [{"binary_name": "openssl", "version": "1.0.2a"}]
        self.assertEqual(profile_order_for_task_group(config, tasks), ("shared", "static"))

        tasks[0]["version"] = "3.5.4"
        self.assertEqual(profile_order_for_task_group(config, tasks), ("static", "shared"))

    def test_openssl_builds_one_tag_once_for_multiple_binary_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = BuildConfig(
                project="openssl",
                repo=root / "repo",
                output=root / "output",
                db_path=root / "output" / "openssl.sqlite",
                vendor_product="openssl:openssl",
                latest=0,
                cves=[],
                compiler="gcc",
                opt="-O2",
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
                architecture="x86_64",
            )
            tasks = [
                {
                    "cve_id": cve_id,
                    "label": "patch",
                    "tag": "openssl-3.5.4",
                    "version": "3.5.4",
                    "binary_name": binary_name,
                    "compiler": "gcc",
                    "opt": "-O2",
                    "architecture": "x86_64",
                    "output_path": "",
                }
                for cve_id, binary_name in (
                    ("CVE-1", "libcrypto"),
                    ("CVE-2", "libcrypto"),
                    ("CVE-3", "libssl"),
                    ("CVE-4", "openssl"),
                )
            ]
            compiler = FakeOpenSSLCompiler(root)
            mapped: list[tuple[str, int]] = []

            def record_mapping(db, build_config, task, path, related, log, source):
                mapped.append((task["binary_name"], len(related)))
                return True

            with (
                patch("binarybuild.target_build.map_built_binary", side_effect=record_mapping),
                patch("binarybuild.target_build.remove_worktrees", return_value=1),
            ):
                failed = run_target_build_local(config, FakeDB(), tasks, compiler)

            self.assertEqual(failed, [])
            self.assertEqual(compiler.compile_calls, [("openssl-3.5.4", "shared")])
            self.assertEqual(len(compiler.copy_calls), 3)
            self.assertEqual(sorted(mapped), [("libcrypto", 2), ("libssl", 1), ("openssl", 1)])


if __name__ == "__main__":
    unittest.main()
