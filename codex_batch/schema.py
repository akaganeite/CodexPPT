from __future__ import annotations

from pathlib import Path

from .io import write_json


def write_result_schema(path: Path) -> None:
    schema = {
        "type": "object",
        "required": ["results"],
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["cve", "binary", "status", "confidence", "evidence", "reasoning"],
                    "properties": {
                        "cve": {"type": "string"},
                        "binary": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": ["present", "absent", "not_affected", "inconclusive", "not_found"],
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["high", "medium", "low"],
                        },
                        "evidence": {"type": "array", "items": {"type": "string"}},
                        "reasoning": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
        },
        "additionalProperties": False,
    }
    write_json(path, schema)
