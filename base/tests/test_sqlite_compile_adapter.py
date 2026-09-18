from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from binarybuild.compile.sqlite import configure_optional_flags, profile_definitions
from binarybuild.reference_build import profile_order_for_task
from types import SimpleNamespace


class SQLiteCompileAdapterTests(unittest.TestCase):
    def test_reference_features_are_explicit_and_have_no_core_only_fallback(self) -> None:
        self.assertEqual(profile_definitions("static"), [])
        self.assertEqual(profile_definitions("shared"), [])
        self.assertEqual(profile_definitions("static-debug"), ["-DSQLITE_DEBUG"])
        self.assertEqual(profile_definitions("static-fts5"), ["-DSQLITE_ENABLE_FTS5"])
        self.assertEqual(profile_definitions("static-session"), [
            "-DSQLITE_ENABLE_SESSION", "-DSQLITE_ENABLE_PREUPDATE_HOOK"])
        self.assertEqual(profile_definitions("shared-explain-comments"), [
            "-DSQLITE_ENABLE_EXPLAIN_COMMENTS"])
        config = SimpleNamespace(project="sqlite")
        for cve, feature in [("CVE-2020-11656", "debug"), ("CVE-2023-7104", "session"),
                             ("CVE-2025-7709", "fts5")]:
            self.assertEqual(profile_order_for_task(config, {"cve_id": cve, "diff_path": "/nonexistent/na35-test.diff"}),
                             (f"static-{feature}", f"shared-{feature}"))

    def test_disable_tcl_is_only_used_when_configure_supports_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            configure = worktree / "configure"

            configure.write_text("  --disable-tcl  do not build TCL extension\n", encoding="utf-8")
            self.assertEqual(configure_optional_flags(worktree), ["--disable-tcl"])

            configure.write_text("  --disable-readline\n", encoding="utf-8")
            self.assertEqual(configure_optional_flags(worktree), [])


if __name__ == "__main__":
    unittest.main()
