from __future__ import annotations

import unittest

from deployed.candidate_discovery.behavior_backfill import reusable_behavior


def behavior(function: str, *, patch_source: bool = True) -> dict:
    item = {
        "root_cause_analysis": {"summary": "root"},
        "patch_intent_analysis": {"summary": "intent"},
        "function_anchors": {function: [{"anchor": str(index)} for index in range(5)]},
    }
    if patch_source:
        item["patch_source"] = {"commit": "abc", "locations": []}
    return item


class BehaviorBackfillTests(unittest.TestCase):
    def test_reuses_only_entries_complete_for_deployed_functions(self) -> None:
        metadata = {
            "CVE-2024-0001": {"functions": ["target"]},
            "CVE-2024-0002": {"functions": ["other"]},
        }
        deployed = {"CVE-2024-0001": behavior("target")}
        base = {
            "CVE-2024-0001": behavior("target"),
            "CVE-2024-0002": behavior("other", patch_source=False),
        }
        reused, missing = reusable_behavior(list(metadata), metadata, deployed, base)
        self.assertEqual(list(reused), ["CVE-2024-0001"])
        self.assertEqual(missing, ["CVE-2024-0002"])


if __name__ == "__main__":
    unittest.main()
