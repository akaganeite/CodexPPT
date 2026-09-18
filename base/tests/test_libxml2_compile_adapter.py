from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from binarybuild.compile import libxml2
from test_support import make_config


class Libxml2CompileAdapterTests(unittest.TestCase):
    def test_legacy_xz_uses_real_header_checks_without_changing_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"PKG_CONFIG": "custom-pkg-config"}):
            root = Path(tmp)
            source = root / "xzlib.c"
            config = make_config(root, [], "gcc", "-O0")
            for guard, expected in (
                ("#ifdef HAVE_LZMA_H", "false"),
                ("#ifdef LIBXML_LZMA_ENABLED", "custom-pkg-config"),
                (None, "custom-pkg-config"),
            ):
                with self.subTest(guard=guard):
                    if guard is None:
                        source.unlink()
                    else:
                        source.write_text(guard + "\n#endif\n", encoding="utf-8")
                    env = libxml2.configure_env(config, root)
                    self.assertEqual(env["PKG_CONFIG"], expected)
                    self.assertNotIn("-DHAVE_LZMA_H", env["CFLAGS"])
                    if guard is not None:
                        self.assertEqual(source.read_text(), guard + "\n#endif\n")
            self.assertEqual(os.environ["PKG_CONFIG"], "custom-pkg-config")

    def test_cross_configure_preserves_central_tools_flags_and_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"PKG_CONFIG": "native-pkg-config"}):
            root = Path(tmp)
            for compiler in ("gcc", "clang"):
                config = make_config(root, [], compiler, "-O0", "aarch64")
                toolchain = config.toolchain
                for source in ("#ifdef HAVE_LZMA_H", "#ifdef LIBXML_LZMA_ENABLED"):
                    with self.subTest(compiler=compiler, source=source):
                        (root / "xzlib.c").write_text(source + "\n#endif\n", encoding="utf-8")
                        env = libxml2.configure_env(config, root)
                        self.assertEqual(env["PKG_CONFIG"], "false")
                        for key, value in {
                            "CC": toolchain.c_compiler, "CXX": toolchain.cxx_compiler,
                            "AR": toolchain.ar, "RANLIB": toolchain.ranlib, "NM": toolchain.nm,
                            "OBJDUMP": toolchain.objdump, "OBJCOPY": toolchain.objcopy,
                            "STRIP": toolchain.strip, "READELF": toolchain.readelf,
                        }.items():
                            self.assertEqual(env[key], value)
                        for flag in toolchain.compiler_flags:
                            for variable in ("CFLAGS", "CXXFLAGS", "LDFLAGS"):
                                self.assertIn(flag, env[variable])
                        for profile in ("static", "shared"):
                            for command in libxml2.configure_commands(config, root, profile):
                                self.assertIn(f"--host={toolchain.configure_host}", command)
                self.assertEqual(
                    libxml2.target_filename(config, "v2.9.2", "xmllint"),
                    config.target_binary_name("v2.9.2", "xmllint"),
                )
                self.assertIn("aarch64", libxml2.target_filename(config, "v2.9.2", "xmllint"))
            native = make_config(root, [], "gcc", "-O0")
            self.assertEqual(libxml2.target_filename(native, "v2.9.2", "xmllint"), "demo-v2.9.2-xmllint-gcc-O0")
            self.assertEqual(libxml2.target_filename("libxml2", "v2.9.2", "xmllint"), "libxml2-v2.9.2-xmllint")

    def test_successful_fallback_retains_failed_command_logs(self) -> None:
        for policy in ("none", "success", "all"):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                worktree = root / "worktree"
                worktree.mkdir()
                (worktree / "xzlib.c").write_text("#ifdef HAVE_LZMA_H\n#endif\n", encoding="utf-8")
                config = make_config(root, [], "gcc", "-O0")
                config.cleanup_build_logs = policy
                outcomes: dict[Path, bool] = {}

                def run(command, *, cwd, log_path, env):
                    if command[0] == "autoreconf":
                        (worktree / "configure").touch()
                        (worktree / "Makefile.in").touch()
                    if command[0] not in ("libtoolize", "autoreconf"):
                        self.assertEqual(env["PKG_CONFIG"], "false")
                    # Exercise failed bootstrap/configure and a nonzero make
                    # that nevertheless produced a usable ELF candidate.
                    ok = command[0] == "autoreconf" or log_path.name.endswith("configure-2.log")
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    log_path.write_text(f"returncode: {0 if ok else 1}\n", encoding="utf-8")
                    outcomes[log_path] = ok
                    return SimpleNamespace(ok=ok)

                with (
                    patch.object(libxml2, "ensure_worktree", return_value=worktree),
                    patch.object(libxml2, "resolve_commit", return_value="abc123"),
                    patch.object(libxml2, "current_log_root", return_value=root / "logs"),
                    patch.object(libxml2, "run_command", side_effect=run),
                    patch.object(libxml2, "candidates_for_binary", return_value=[(worktree / "xmllint", "xmllint")]),
                ):
                    result = libxml2.compile_commit(config, "abc123", "reference_build", Mock())
                self.assertTrue(result.ok)
                self.assertEqual(len(outcomes), 5)
                self.assertEqual(set(result.log_paths), {str(path) for path in outcomes})
                self.assertTrue(libxml2.has_build_marker(config, worktree, "static"))
                for path, ok in outcomes.items():
                    self.assertEqual(path.exists(), policy == "none" or not ok, str(path))

    def test_failed_build_retains_all_logs_even_with_all_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root, [], "gcc", "-O0")
            config.cleanup_build_logs = "all"

            def run(command, *, cwd, log_path, env):
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text("returncode: 1\n", encoding="utf-8")
                return SimpleNamespace(ok=False)

            with (
                patch.object(libxml2, "ensure_worktree", return_value=root),
                patch.object(libxml2, "resolve_commit", return_value="abc123"),
                patch.object(libxml2, "current_log_root", return_value=root / "logs"),
                patch.object(libxml2, "run_command", side_effect=run),
                patch.object(libxml2, "remove_build_logs") as cleanup,
            ):
                result = libxml2.compile_commit(config, "abc123", "reference_build", Mock())
            self.assertFalse(result.ok)
            self.assertEqual(len(result.log_paths), 2)
            self.assertTrue(all(Path(path).is_file() for path in result.log_paths))
            self.assertFalse(libxml2.marker_path(root, "static").exists())
            cleanup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
