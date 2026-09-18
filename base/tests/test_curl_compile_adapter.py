from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from binarybuild.compile import curl
from tests.test_support import make_config, write_elf


def shared_elf(path: Path, architecture: str = "x86_64") -> None:
    write_elf(path, architecture)
    with path.open("r+b") as stream:
        stream.seek(16)
        stream.write(b"\x03\x00")


class CurlCompileAdapterTests(unittest.TestCase):
    def test_gnutls_configure_never_falls_back_to_another_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root, [], "gcc", "-O0")
            for profile in ("static-gnutls", "shared-gnutls"):
                commands = curl.configure_commands(config, profile, root)
                self.assertEqual(len(commands), 2)
                for command in commands:
                    self.assertNotIn("--enable-debug", command)
                    self.assertIn("--disable-curldebug", command)
                    self.assertIn("--with-gnutls", command)
                    self.assertNotIn("--without-gnutls", command)
                    self.assertNotIn("--without-ssl", command)
                    self.assertIn("--without-openssl", command)
                self.assertEqual(curl.compile_cmake_fallback(config, root, root, "commit", profile, Mock()), (False, []))
            cross = make_config(root, [], "gcc", "-O0", "aarch64")
            self.assertEqual(curl.configure_commands(cross, "shared-gnutls", root), [])
            with patch.object(curl, "ensure_worktree") as ensure:
                self.assertFalse(curl.compile_commit(cross, "commit", "test", Mock(), "shared-gnutls").ok)
                ensure.assert_not_called()
            for command in curl.configure_commands(cross, "shared", root):
                self.assertIn(f"--host={cross.toolchain.configure_host}", command)
                self.assertNotIn("--with-gnutls", command)
            self.assertEqual(curl.target_filename(cross, "7.34", "libcurl-gnutls"), cross.target_binary_name("7.34", "libcurl-gnutls"))

    def test_make_restores_debug_and_optimization_flags_without_debug_macros(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Makefile").write_text("CFLAGS = -pthread \\\n -O2\nCXXFLAGS = \nCPPFLAGS = -DUNRELATED\n")
            (root / "lib").mkdir()
            (root / "lib" / "Makefile").touch()
            config = make_config(root, [], "gcc", "-O0")
            env = curl.build_env(config)
            for command in curl.make_commands(root, env):
                flags = next(arg for arg in command if arg.startswith("CFLAGS="))
                self.assertIn("-pthread", flags)
                self.assertIn("-g3", flags)
                self.assertGreater(flags.index("-O0"), flags.index("-O2"))
                self.assertNotIn("DEBUGBUILD", flags)
                cxx_flags = next(arg for arg in command if arg.startswith("CXXFLAGS="))
                self.assertNotIn("CPPFLAGS", cxx_flags)
                self.assertIn("-g3", cxx_flags)

    def test_historical_nettle_probe_patch_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "configure.ac"
            source.write_text("AC_CHECK_LIB(nettle, nettle_MD5Init, [ USE_GNUTLS_NETTLE=1 ])\n")
            configure = root / "configure"
            configure.touch()
            curl.apply_worktree_compat_patches(root, Mock(), "commit")
            self.assertFalse(configure.exists())
            repaired = source.read_text()
            self.assertIn("AC_CHECK_LIB(nettle, nettle_md5_init", repaired)
            configure.touch()
            curl.apply_worktree_compat_patches(root, Mock(), "commit")
            self.assertTrue(configure.exists())
            self.assertEqual(repaired, source.read_text())

    def test_companion_selection_requires_matching_marker_and_roundtrips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root, [], "gcc", "-O0")
            primary = root / "lib" / ".libs" / "libcurl.so.4"
            companion = root / ".agentic-gnutls"
            backend = companion / "lib" / ".libs" / "libcurl.so.4"
            (root / ".git").touch()
            shared_elf(primary)
            shared_elf(backend)
            curl.write_build_marker(config, root, "shared")

            def symbols(path, nm):
                self.assertEqual(nm, config.toolchain.nm)
                return {"gtls_connect_step3"} if path == backend else {"ossl_connect_step1"}

            with patch.object(curl, "symbol_names", side_effect=symbols):
                self.assertIsNone(curl.find_binary_by_name(root, "libcurl-gnutls", "shared"))
                curl.write_build_marker(config, companion, "shared-gnutls")
                self.assertEqual(curl.choose_binary(root, [], profile="shared").path, primary)
                match = curl.choose_binary(root, ["gtls_connect_step3"], profile="shared")
                self.assertEqual((match.path, match.binary_name, match.missing), (backend, "libcurl-gnutls", []))
                self.assertEqual(curl.find_binary_by_name(root, match.binary_name, "shared"), backend)
                self.assertEqual(curl.choose_binary(root, [], preferred=match.binary_name, profile="shared").path, backend)
                missing = curl.choose_binary(root, ["gtls_connect_step3", "schannel_connect_step3"], profile="shared").missing
                self.assertEqual(missing, ["schannel_connect_step3"])
                dest = root / "copy"
                curl.copy_binary(backend, dest)
                self.assertEqual(dest.read_bytes(), backend.read_bytes())
                self.assertEqual(curl.artifact_build_metadata(backend), curl.build_metadata(companion, "shared-gnutls"))
                # Resume must retry the primary even if the companion survives.
                primary.unlink()
                self.assertFalse(curl.has_built_curl(root, "shared", config))
                shared_elf(primary)
                for stale in (make_config(root, [], "gcc", "-O2"), make_config(root, [], "gcc", "-O0", "aarch64")):
                    curl.write_build_marker(stale, companion, "shared-gnutls")
                    self.assertIsNone(curl.find_binary_by_name(root, "libcurl-gnutls", "shared"))

    def test_explicit_gnutls_compile_selection_and_resume_roundtrip(self) -> None:
        for profile, relative, binary_name in (
            ("shared-gnutls", "lib/.libs/libcurl.so", "libcurl-gnutls"),
            ("static-gnutls", "src/curl", "curl-gnutls"),
        ):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config = make_config(root, [], "gcc", "-O0")
                config.toolchain = replace(config.toolchain, nm="contract-nm")
                (root / ".git").touch()
                source = root / ".agentic-gnutls"
                backend = source / relative
                shared_elf(backend)
                functions = ["Curl_gtls_verifyserver", "gtls_client_init"]

                def symbols(path, nm):
                    self.assertEqual(nm, config.toolchain.nm)
                    return {"Curl_ssl_gnutls", *functions}

                def finish_build(*args):
                    curl.write_build_marker(config, source, profile)
                    return curl.BuildOutput("commit", source, True, ["build.log"])

                with patch.object(curl, "ensure_worktree", return_value=root), \
                     patch.object(curl.subprocess, "run", return_value=Mock(stdout="commit\n")), \
                     patch.object(curl, "current_log_root", return_value=root / "logs"), \
                     patch.object(curl, "probe_gnutls", return_value=True) as probe, \
                     patch.object(curl, "prepare_gnutls_source", return_value=(source, [])) as prepare, \
                     patch.object(curl, "compile_worktree") as build, \
                     patch.object(curl, "symbol_names", side_effect=symbols), \
                     patch.object(curl, "remove_build_logs") as cleanup:
                    build.return_value = curl.BuildOutput("commit", source, False, ["failed.log"], "build failed")
                    failed = curl.compile_commit(config, "commit", "test", Mock(), profile)
                    self.assertFalse(failed.ok)
                    self.assertIn("failed.log", failed.log_paths)
                    self.assertFalse(curl.has_build_marker(config, root, profile))
                    self.assertIsNone(curl.choose_binary(root, functions, profile=profile))
                    cleanup.assert_not_called()

                    build.side_effect = finish_build
                    result = curl.compile_commit(config, "commit", "test", Mock(), profile)
                    self.assertTrue(result.ok)
                    self.assertEqual(result.worktree, root)
                    self.assertTrue(curl.has_build_marker(config, result.worktree, profile))
                    self.assertTrue(curl.has_built_curl(result.worktree, profile, config))
                    match = curl.choose_binary(result.worktree, functions, profile=profile)
                    self.assertIsNotNone(match)
                    self.assertEqual((match.path, match.binary_name, match.missing), (backend, binary_name, []))
                    self.assertEqual(curl.find_binary_by_name(result.worktree, binary_name, profile), backend)
                    self.assertEqual(curl.artifact_build_metadata(backend), curl.build_metadata(source, profile))
                    cleanup.assert_called_once()

                    # A complete archived build can restore the public root marker.
                    curl.build_marker_path(root, profile).unlink()
                    self.assertIsNone(curl.choose_binary(root, functions, profile=profile))
                    probe.reset_mock()
                    prepare.reset_mock()
                    build.reset_mock()
                    resumed = curl.compile_commit(config, "commit", "test", Mock(), profile)
                    self.assertTrue(resumed.ok)
                    self.assertEqual(resumed.worktree, root)
                    self.assertTrue(curl.has_built_curl(root, profile, config))
                    self.assertEqual(curl.choose_binary(root, functions, profile=profile), match)
                    probe.assert_not_called()
                    prepare.assert_not_called()
                    build.assert_not_called()

                    marker = curl.build_marker_path(source, profile)
                    signature = marker.read_text()
                    for old, new in (
                        (curl.ADAPTER_VERSION, "outdated-adapter"),
                        ("architecture=x86_64", "architecture=aarch64"),
                        ("opt=-O0", "opt=-O2"),
                        ("nm=contract-nm", "nm=wrong-nm"),
                        (f"profile={profile}", f"profile={profile}-gnutls"),
                    ):
                        marker.write_text(signature.replace(old, new))
                        self.assertIsNone(curl.choose_binary(root, functions, profile=profile))
                        self.assertIsNone(curl.find_binary_by_name(root, binary_name, profile))
                        self.assertFalse(curl.has_built_curl(root, profile, config))
                    marker.write_text(signature)
                    shared_elf(backend, "aarch64")
                    self.assertIsNone(curl.find_binary_by_name(root, binary_name, profile))

    def test_plain_profile_has_no_implicit_gnutls_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root, [], "gcc", "-O0")
            log = Mock()
            output = curl.BuildOutput("commit", root, True, [], "")

            with patch.object(curl, "ensure_worktree", return_value=root), \
                 patch.object(curl.subprocess, "run", return_value=Mock(stdout="commit\n")), \
                 patch.object(curl, "current_log_root", return_value=root / "logs"), \
                 patch.object(curl, "compile_worktree", return_value=output) as compile_worktree, \
                 patch.object(curl, "probe_gnutls") as probe:
                result = curl.compile_commit(config, "commit", "test", log, "shared")
            self.assertIs(result, output)
            compile_worktree.assert_called_once()
            self.assertEqual(compile_worktree.call_args.args[5], "shared")
            probe.assert_not_called()

    @unittest.skipUnless(shutil.which("gcc") and shutil.which("nm"), "requires native C toolchain")
    def test_undefined_import_is_not_a_function_implementation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "symbols.c"
            binary = root / "libcurl.so"
            source.write_text(
                "extern int gtls_connect_step3(void);\n"
                "static int local_helper(void) { return 1; }\n"
                "int real_function(void) { return local_helper() + gtls_connect_step3(); }\n"
            )
            subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-g", str(source), "-o", str(binary)], check=True)
            names = curl.symbol_names(binary)
            self.assertIn("real_function", names)
            self.assertIn("local_helper", names)
            self.assertNotIn("gtls_connect_step3", names)

    def test_cross_copy_requires_central_readelf_on_both_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root, [], "gcc", "-O0", "aarch64")
            (root / ".git").touch()
            source = root / "libcurl.so"
            dest = root / "copy"
            shared_elf(source, "aarch64")
            curl.write_build_marker(config, root, "shared")
            with patch.object(curl, "readelf_machine", return_value="AArch64") as readelf:
                curl.copy_binary(source, dest)
                self.assertTrue(dest.exists())
                self.assertEqual(readelf.call_count, 2)
                self.assertTrue(all(call.args[1] == config.toolchain.readelf for call in readelf.call_args_list))
            with patch.object(curl, "readelf_machine", return_value="Advanced Micro Devices X86-64"):
                curl.copy_binary(source, dest)
                self.assertFalse(dest.exists())


if __name__ == "__main__":
    unittest.main()
