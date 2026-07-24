"""Host-side filesystem, environment, and preflight helpers.

All host I/O lives here so the rest of the harness stays testable offline. None of
these functions are exposed to the model except for answer-scrubbed CVE metadata
and bounded target-binary facts used for investigation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from claudeagent.common import expand, load_json


def load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"").strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_env_files(extra_env_file: str = "") -> None:
    from claudeagent.common import ROOT

    load_env_file(ROOT / ".env")
    if extra_env_file:
        load_env_file(expand(extra_env_file))


def import_env_from_interactive_shell(keys: list[str]) -> list[str]:
    missing = [key for key in keys if not os.environ.get(key)]
    if not missing:
        return []
    py = (
        "import json, os; "
        f"keys={missing!r}; "
        "print(json.dumps({k: os.environ.get(k, '') for k in keys}))"
    )
    try:
        proc = subprocess.run(
            ["zsh", "-ic", f"python3 -c {shlex.quote(py)}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        return []
    imported = []
    for key, value in data.items():
        if value and not os.environ.get(key):
            os.environ[key] = value
            imported.append(key)
    return imported


def run_host_cmd(argv: list[str], timeout: int = 240, max_output_chars: int | None = None) -> dict[str, Any]:
    start = time.time()
    try:
        proc = subprocess.run(
            argv,
            text=True,
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "elapsed_sec": round(time.time() - start, 3),
            "cmd": " ".join(shlex.quote(x) for x in argv),
            "stdout": proc.stdout if max_output_chars is None else proc.stdout[-max_output_chars:],
            "stderr": proc.stderr if max_output_chars is None else proc.stderr[-max_output_chars:],
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return {
            "ok": False,
            "returncode": None,
            "elapsed_sec": round(time.time() - start, 3),
            "cmd": " ".join(shlex.quote(x) for x in argv),
            "stdout": stdout if max_output_chars is None else stdout[-max_output_chars:],
            "stderr": stderr if max_output_chars is None else stderr[-max_output_chars:],
            "error": f"timeout after {timeout}s",
        }
    except FileNotFoundError as exc:
        return {
            "ok": False,
            "returncode": None,
            "elapsed_sec": round(time.time() - start, 3),
            "cmd": " ".join(shlex.quote(x) for x in argv),
            "stdout": "",
            "stderr": "",
            "error": f"command not found: {exc}",
        }


def binary_sha256(binary: Path) -> str:
    h = hashlib.sha256()
    with binary.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def symbol_hint(binary: Path) -> dict[str, Any]:
    if not binary.is_file():
        return {"has_useful_symbols": False, "reason": "binary missing", "sample_defined_text_symbols": []}
    result = run_host_cmd(["nm", "-an", "--defined-only", str(binary)], timeout=30, max_output_chars=24000)
    samples: list[str] = []
    for raw in str(result.get("stdout", "")).splitlines():
        parts = raw.strip().split()
        if len(parts) >= 3 and parts[1].lower() in {"t", "w"} and not parts[2].startswith((".", "$")):
            samples.append(raw.strip())
            if len(samples) >= 12:
                break
    return {
        "has_useful_symbols": len(samples) >= 3,
        "reason": "defined function symbols are available" if len(samples) >= 3 else "too few defined function symbols for nm anchoring",
        "nm_returncode": result.get("returncode"),
        "sample_defined_text_symbols": samples,
    }


def preflight_detection_inputs(binary: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    path = expand(binary)
    file_info = run_host_cmd(["file", str(path)], timeout=30, max_output_chars=4000) if path.is_file() else {}
    preflight = {
        "ok": path.is_file(),
        "binary": {
            "path": str(path),
            "exists": path.is_file(),
            "size": path.stat().st_size if path.is_file() else 0,
            "sha256": binary_sha256(path) if path.is_file() else "",
            "file": str(file_info.get("stdout", "")).strip(),
        },
        "symbol_hint": symbol_hint(path),
    }
    return preflight


def load_cve_metadata(args: argparse.Namespace) -> dict[str, Any]:
    if args.cve_inline_json:
        data = json.loads(args.cve_inline_json)
    elif args.cve_json:
        data = load_json(args.cve_json)
    elif args.metadata_json:
        all_data = load_json(args.metadata_json)
        if not args.cve_id:
            raise SystemExit("--cve-id is required with --metadata-json")
        if isinstance(all_data, dict) and args.cve_id in all_data:
            data = all_data[args.cve_id]
        elif isinstance(all_data, list):
            matches = [
                item for item in all_data
                if isinstance(item, dict) and item.get("cve_id") == args.cve_id
            ]
            if not matches:
                raise SystemExit(f"CVE not found in metadata JSON: {args.cve_id}")
            data = matches[0]
        else:
            raise SystemExit(f"CVE not found in metadata JSON: {args.cve_id}")
    else:
        raise SystemExit("provide --cve-json, --cve-inline-json, or --metadata-json + --cve-id")
    if not isinstance(data, dict):
        raise SystemExit("CVE metadata must be a JSON object")
    data = dict(data)
    if "cve_id" not in data and args.cve_id:
        data["cve_id"] = args.cve_id
    if "project" not in data:
        data["project"] = "curl"
    return data
