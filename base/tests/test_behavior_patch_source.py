from __future__ import annotations

import unittest
from pathlib import Path

from RCA.patch_source import enrich_behavior_data


class BehaviorPatchSourceTest(unittest.TestCase):
    def test_enriches_locations_without_collapsing_same_named_static_functions(self) -> None:
        cve_id = "CVE-2025-0001"
        behavior = {
            cve_id: {"root_cause_analysis": {"summary": "x"}},
            "CVE-2025-OTHER": {"untouched": True},
        }
        source = {
            "cves": {
                cve_id: {
                    "function_analyses": [
                        {
                            "function": {"name": "decode_frame", "file": "lib/a.c", "commit": "abc123"},
                            "metadata": {"function": {"line_range": [10, 40]}},
                            "step_b": {"changed_lines": [{"line": 22}]},
                            "pre_patch_source_sink": {"old_changed_lines": [{"line": 20}]},
                        },
                        {
                            "function": {"name": "decode_frame", "file": "lib/b.c", "commit": "abc123"},
                            "metadata": {"function": {"line_range": [50, 90]}},
                            "step_b": {"changed_lines": [{"line": 61}, {"line": 62}]},
                            "pre_patch_source_sink": {"old_changed_lines": [{"line": 59}]},
                        },
                    ]
                }
            }
        }

        self.assertEqual(
            enrich_behavior_data(behavior, source, Path("/missing-repo"), {cve_id: "abc123"}, [cve_id]),
            1,
        )
        self.assertEqual(
            behavior[cve_id]["patch_source"],
            {
                "commit": "abc123",
                "locations": [
                    {
                        "function": "decode_frame",
                        "file": "lib/a.c",
                        "function_line_range": [10, 40],
                        "changed_old_lines": [20],
                        "changed_new_lines": [22],
                    },
                    {
                        "function": "decode_frame",
                        "file": "lib/b.c",
                        "function_line_range": [50, 90],
                        "changed_old_lines": [59],
                        "changed_new_lines": [61, 62],
                    },
                ],
            },
        )
        self.assertEqual(behavior["CVE-2025-OTHER"], {"untouched": True})
        self.assertEqual(
            enrich_behavior_data(behavior, source, Path("/missing-repo"), {cve_id: "abc123"}, [cve_id]),
            0,
        )


if __name__ == "__main__":
    unittest.main()
