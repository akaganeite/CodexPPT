from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from binarybuild.compile.binutils import has_regular_symbol_table


class BinutilsAdapterSymbolTests(unittest.TestCase):
    def test_regular_symbol_table_requires_successful_nonempty_nm_output(self) -> None:
        with patch("binarybuild.compile.binutils.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "binary:00000000 T function\n"
            self.assertTrue(has_regular_symbol_table(Path("binary"), "nm"))

            run.return_value.stdout = ""
            self.assertFalse(has_regular_symbol_table(Path("binary"), "nm"))

            run.return_value.returncode = 1
            self.assertFalse(has_regular_symbol_table(Path("binary"), "nm"))


if __name__ == "__main__":
    unittest.main()
