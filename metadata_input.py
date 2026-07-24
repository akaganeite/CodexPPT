"""Validation and stable fingerprinting for investigator metadata."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


_FORBIDDEN_KEY_NAMES = {
    "answer",
    "answerlabel",
    "answerstatus",
    "answerverdict",
    "artifactname",
    "artifactpath",
    "artifactversion",
    "binaryfilename",
    "binaryname",
    "binarypath",
    "binaryversion",
    "expected",
    "expectedanswer",
    "expectedlabel",
    "expectedresult",
    "expectedstatus",
    "expectedverdict",
    "goldlabel",
    "groundtruth",
    "groundtruthlabel",
    "groundtruthstatus",
    "groundtruthverdict",
    "ispatched",
    "isvulnerable",
    "knownpatched",
    "knownverdict",
    "knownvulnerable",
    "label",
    "predicted",
    "prediction",
    "targetfilename",
    "targetbinary",
    "targetname",
    "targetpath",
    "targetversion",
    "testlabel",
    "verdict",
}

_ANSWER_VALUE_RE = re.compile(
    r"\b(?:answer(?:[ _-](?:label|status|verdict))?|"
    r"expected(?:[ _-](?:answer|label|result|status|verdict))?|"
    r"ground[ _-]?truth(?:[ _-](?:label|status|verdict))?|"
    r"known[ _-]?verdict|prediction|test[ _-]?label)\s*[:=]\s*[\"']?"
    r"(?:present|absent|not[ _-]?affected|inconclusive|patched|vuln(?:erable)?)\b",
    re.IGNORECASE,
)
_TARGET_IDENTITY_VALUE_RE = re.compile(
    r"\b(?:artifact|binary|target)[ _-]*(?:filename|name|path|version)\s*[:=]",
    re.IGNORECASE,
)
_HOST_ABSOLUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"/(?:home|root|Users|media|mnt|tmp)(?:/|\\)|"
    r"[A-Za-z]:[\\/](?:Users|Documents[ _]and[ _]Settings|workspace|repos?|src)[\\/]"
    r")",
    re.IGNORECASE,
)


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def metadata_sha256(metadata: dict[str, Any], cve_id: str | None = None) -> str:
    """Return a stable digest for the metadata actually supplied to the model."""
    payload = dict(metadata)
    if cve_id and not payload.get("cve_id"):
        payload["cve_id"] = cve_id
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_metadata_prompt_input(metadata: Any) -> None:
    """Reject answer-bearing or target-identity fields before model exposure."""
    if not isinstance(metadata, dict):
        raise ValueError("raw CVE metadata must be an object")

    forbidden_paths: list[str] = []
    forbidden_value_paths: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}/{key}"
                if _normalized_key(key) in _FORBIDDEN_KEY_NAMES:
                    forbidden_paths.append(child_path)
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}/{index}")
        elif isinstance(value, str) and (
            _ANSWER_VALUE_RE.search(value)
            or _TARGET_IDENTITY_VALUE_RE.search(value)
            or _HOST_ABSOLUTE_PATH_RE.search(value)
        ):
            forbidden_value_paths.append(path)

    visit(metadata, "$")
    rejected_paths = forbidden_paths + forbidden_value_paths
    if rejected_paths:
        preview = rejected_paths[:12]
        suffix = "" if len(rejected_paths) <= 12 else f" (+{len(rejected_paths) - 12} more)"
        raise ValueError(
            "metadata contains answer-bearing data, target identity, or a host-local path at: "
            f"{preview}{suffix}"
        )
