from __future__ import annotations

import json
import re
from typing import Any


STATUS_VALUES = {"present", "absent", "not_affected", "inconclusive", "not_found", "error"}


def extract_json_object(text: str) -> Any:
    text = text.strip()
    if not text:
        raise ValueError("empty model output")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fence = re.search(r"```(?:json|js)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        return json.loads(fence.group(1))

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError("could not find a JSON object in model output")


def validate_cve_result(cve: str, binaries: list[str], obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("result root is not an object")

    if isinstance(obj.get("results"), list):
        per_binary = {
            str(row.get("binary")): row
            for row in obj["results"]
            if isinstance(row, dict) and str(row.get("cve", cve)) == cve
        }
    elif cve in obj and isinstance(obj[cve], dict):
        per_binary = obj[cve]
    else:
        # Be permissive if the model returns the per-binary object directly.
        per_binary = obj

    out: dict[str, Any] = {}
    for binary in binaries:
        row = per_binary.get(binary)
        if not isinstance(row, dict):
            out[binary] = {
                "status": "error",
                "confidence": "low",
                "evidence": ["codex output did not contain this requested binary"],
                "reasoning": "Missing per-binary result in final JSON.",
            }
            continue

        status = str(row.get("status", "error"))
        if status not in STATUS_VALUES:
            status = "error"

        evidence = row.get("evidence", [])
        if isinstance(evidence, str):
            evidence = [evidence]
        if not isinstance(evidence, list):
            evidence = [repr(evidence)]

        out[binary] = {
            "status": status,
            "confidence": str(row.get("confidence", "low")),
            "evidence": [str(x) for x in evidence],
            "reasoning": str(row.get("reasoning", "")),
        }
    return out


def cve_has_status(result: Any, status: str) -> bool:
    if not isinstance(result, dict):
        return False
    return any(isinstance(row, dict) and row.get("status") == status for row in result.values())


def error_result(cve: str, binaries: list[str], reason: str, evidence: str) -> dict[str, Any]:
    return {
        binary: {
            "status": "error",
            "confidence": "low",
            "evidence": [evidence],
            "reasoning": reason,
        }
        for binary in binaries
    }
