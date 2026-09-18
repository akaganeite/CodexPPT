from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from binarybuild.compile import openssl
from test_support import make_config, write_elf


def write_shared_elf(path: Path, architecture: str = "x86_64") -> None:
    write_elf(path, architecture)
    with path.open("r+b") as stream:
        stream.seek(16)
        stream.write(b"\x03\x00")


class OpenSSLCompileAdapterTests(unittest.TestCase):
    def test_legacy_selection_preserves_priority_and_roundtrips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root, [], "gcc", "-O0")
            (root / ".git").touch()
            legacy = root / "providers" / "legacy.so"
            for path in (root / "libssl.so.3", root / "libcrypto.so.3", root / "apps" / "openssl", legacy):
                write_shared_elf(path)
            write_shared_elf(root / "providers" / "legacy-extra.so")
            (root / "providers" / "liblegacy.a").write_bytes(b"!<arch>\n")
            wanted = "rc4_hmac_md5_set_ctx_params"

            def symbols(path, nm):
                self.assertEqual(nm, config.toolchain.nm)
                return {wanted} if path == legacy else set()

            for profile, first in (("static", "openssl"), ("shared", "libssl")):
                with self.subTest(profile=profile), patch.object(openssl, "symbol_names", side_effect=symbols):
                    openssl.write_build_marker(config, root, profile)
                    candidates = openssl.candidates_for_binary(root, profile)
                    self.assertEqual([name for _, name in candidates].count("legacy"), 1)
                    self.assertEqual(len(candidates), 4)
                    self.assertEqual(openssl.choose_binary(root, [], profile=profile).binary_name, first)
                    match = openssl.choose_binary(root, [wanted], profile=profile)
                    self.assertEqual((match.path, match.binary_name, match.missing), (legacy, "legacy", []))
                    self.assertEqual(openssl.find_binary_by_name(root, "legacy", profile), legacy)
                    self.assertEqual(openssl.choose_binary(root, [], preferred="legacy", profile=profile).path, legacy)
            copied = root / "copied-legacy"
            openssl.copy_binary(legacy, copied)
            self.assertEqual(copied.read_bytes(), legacy.read_bytes())
            self.assertTrue(os.access(copied, os.X_OK))

    def test_declared_legacy_module_is_built_and_required_for_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root, [], "gcc", "-O0")
            makefile = root / "Makefile"
            makefile.write_text(
                "MODULES=engines/test.so \\\n"
                " providers/legacy.so\nbuild_generated:\nbuild_sw:\nlibcrypto.so.3:\n",
                encoding="utf-8",
            )
            write_shared_elf(root / "libcrypto.so.3")
            write_shared_elf(root / "apps" / "openssl")
            for profile in ("static", "shared"):
                openssl.write_build_marker(config, root, profile)
                self.assertFalse(openssl.has_built_openssl(root, profile, config))
            self.assertTrue(openssl.profile_has_expected_output(root, "shared-libcrypto", "x86_64"))
            commands = openssl.make_commands(config, "static", root)
            self.assertEqual(
                [command[-1] for command in commands[:-1]],
                ["build_generated", "apps/openssl", "providers/legacy.so", "build_sw"],
            )
            write_shared_elf(root / "providers" / "legacy.so")
            for profile in ("static", "shared"):
                self.assertTrue(openssl.has_built_openssl(root, profile, config))
                other_config = make_config(root, [], "gcc", "-O2")
                self.assertFalse(openssl.has_built_openssl(root, profile, other_config))
            (root / "providers" / "legacy.so").unlink()
            for text in ("build_generated:\nbuild_sw:\n", "build_apps:\n"):
                makefile.write_text(text, encoding="utf-8")
                for profile in ("static", "shared"):
                    self.assertTrue(openssl.has_built_openssl(root, profile, config))
                    self.assertNotIn("providers/legacy.so", [cmd[-1] for cmd in openssl.make_commands(config, profile, root)])

    def test_aarch64_legacy_selection_and_copy_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root, [], "gcc", "-O0", "aarch64")
            (root / ".git").touch()
            legacy = root / "providers" / "legacy.so"
            copied = root / "copied-legacy"
            openssl.write_build_marker(config, root, "shared")
            write_shared_elf(legacy)
            self.assertIsNone(openssl.find_binary_by_name(root, "legacy", "shared"))
            write_shared_elf(legacy, "aarch64")
            with patch.object(openssl, "readelf_machine", return_value="AArch64") as readelf:
                with patch.object(openssl, "symbol_names", return_value={"required"}) as symbols:
                    self.assertEqual(openssl.choose_binary(root, ["required"], profile="shared").path, legacy)
                    symbols.assert_called_once_with(legacy, nm=config.toolchain.nm)
                self.assertEqual(openssl.find_binary_by_name(root, "legacy", "shared"), legacy)
                readelf.reset_mock()
                openssl.copy_binary(legacy, copied)
                self.assertEqual([call.args for call in readelf.call_args_list], [
                    (legacy, config.toolchain.readelf), (copied, config.toolchain.readelf),
                ])
                self.assertTrue(copied.is_file())
            with patch.object(openssl, "readelf_machine", side_effect=["AArch64", "wrong machine"]):
                openssl.copy_binary(legacy, copied)
                self.assertFalse(copied.exists())
            with patch.object(openssl, "readelf_machine", return_value="wrong machine"):
                self.assertIsNone(openssl.choose_binary(root, ["required"], profile="shared"))
                self.assertIsNone(openssl.find_binary_by_name(root, "legacy", "shared"))
            openssl.build_marker_path(root, "shared").unlink()
            self.assertIsNone(openssl.choose_binary(root, ["required"], profile="shared"))
            self.assertIsNone(openssl.find_binary_by_name(root, "legacy", "shared"))
            openssl.copy_binary(legacy, copied)
            self.assertFalse(copied.exists())

    def test_cross_tools_old_configure_fallback_and_target_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Makefile").write_text("AR=ar $(ARFLAGS) r\nbuild_apps:\n", encoding="utf-8")
            for compiler in ("gcc", "clang"):
                config = make_config(root, [], compiler, "-O0", "aarch64")
                for target in ("linux-aarch64", "linux-generic64"):
                    (root / "Configure").write_text(f'"{target}" => {{}}\n', encoding="utf-8")
                    with self.subTest(compiler=compiler, target=target):
                        with patch.dict(os.environ, {"LDFLAGS": "-L/native", "CPATH": "/native", "PKG_CONFIG": "native"}):
                            env = openssl.build_env(config)
                        self.assertNotIn("CPATH", env)
                        self.assertNotIn("/native", env["LDFLAGS"])
                        self.assertEqual(env["PKG_CONFIG"], "false")
                        for variable, field in (
                            ("CC", "c_compiler"), ("CXX", "cxx_compiler"), ("AR", "ar"),
                            ("RANLIB", "ranlib"), ("NM", "nm"), ("OBJDUMP", "objdump"),
                            ("OBJCOPY", "objcopy"), ("STRIP", "strip"), ("READELF", "readelf"),
                        ):
                            self.assertEqual(env[variable], getattr(config.toolchain, field))
                        for profile in ("static", "shared"):
                            for command in openssl.configure_commands(config, profile, root):
                                self.assertEqual(command[:3], ["perl", "./Configure", target])
                                for flag in config.toolchain.compiler_flags:
                                    self.assertIn(flag, command)
                            for command in openssl.make_commands(config, profile, root):
                                self.assertIn(f"CC={config.toolchain.c_compiler}", command)
                                self.assertIn(f"AR={config.toolchain.ar} $(ARFLAGS) r", command)
                                self.assertIn("CROSS_COMPILE=", command)
                        self.assertEqual(openssl.target_filename(config, "3.0.2", "legacy"), config.target_binary_name("3.0.2", "legacy"))
                        self.assertIn("aarch64", openssl.target_filename(config, "3.0.2", "legacy"))
            native = make_config(root, [], "gcc", "-O0")
            self.assertEqual(openssl.target_filename(native, "3.0.2", "legacy"), "demo-3.0.2-legacy-gcc-O0")
            self.assertEqual(openssl.target_filename("openssl", "3.0.2", "legacy", "gcc", "-O0"), "openssl-3.0.2-legacy-gcc-O0")

    def test_failed_command_logs_survive_successful_fallback(self) -> None:
        for policy in ("none", "success", "all"):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config = make_config(root, [], "gcc", "-O0")
                config.cleanup_build_logs = policy
                (root / "Makefile").write_text("build_sw:\n", encoding="utf-8")
                outcomes: dict[Path, bool] = {}

                def run(command, *, cwd, log_path, env):
                    if command[0] == "configure-good":
                        (root / "Makefile").write_text("depend:\nbuild_generated:\nbuild_sw:\n", encoding="utf-8")
                    if command[-1] == "apps/openssl":
                        write_shared_elf(root / "apps" / "openssl")
                    ok = command[0] == "configure-good" or command[-1] == "build_generated"
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    log_path.write_text(f"returncode: {0 if ok else 1}\n", encoding="utf-8")
                    outcomes[log_path] = ok
                    return SimpleNamespace(ok=ok)

                with (
                    patch.object(openssl, "ensure_worktree", return_value=root),
                    patch.object(openssl.subprocess, "run", return_value=SimpleNamespace(stdout="abc123\n")),
                    patch.object(openssl, "current_log_root", return_value=root / "logs"),
                    patch.object(openssl, "configure_commands", return_value=[["configure-bad"], ["configure-good"]]),
                    patch.object(openssl, "should_run_make_depend", return_value=True),
                    patch.object(openssl, "run_command", side_effect=run),
                ):
                    result = openssl.compile_commit(config, "abc123", "reference_build", Mock())
                self.assertTrue(result.ok)
                self.assertEqual(len(outcomes), 7)
                self.assertEqual(set(result.log_paths), {str(path) for path in outcomes})
                for path, ok in outcomes.items():
                    self.assertEqual(path.exists(), policy == "none" or not ok, str(path))

    def test_completely_failed_build_keeps_all_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root, [], "gcc", "-O0")
            config.cleanup_build_logs = "all"

            def run(command, *, cwd, log_path, env):
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text("returncode: 1\n", encoding="utf-8")
                return SimpleNamespace(ok=False)

            with (
                patch.object(openssl, "ensure_worktree", return_value=root),
                patch.object(openssl.subprocess, "run", return_value=SimpleNamespace(stdout="abc123\n")),
                patch.object(openssl, "current_log_root", return_value=root / "logs"),
                patch.object(openssl, "configure_commands", return_value=[["configure-bad"]]),
                patch.object(openssl, "run_command", side_effect=run),
                patch.object(openssl, "remove_build_logs") as cleanup,
            ):
                result = openssl.compile_commit(config, "abc123", "reference_build", Mock())
            self.assertFalse(result.ok)
            self.assertTrue(all(Path(path).exists() for path in result.log_paths))
            self.assertFalse(openssl.build_marker_path(root, "static").exists())
            cleanup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
