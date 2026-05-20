#!/usr/bin/env python3
"""Generate root-cause and patch-intent metadata with DeepSeek.

Input is the compact project metadata produced by project_source_analysis.py.
The output keeps each CVE object intact and appends:
  - root_cause_analysis
  - patch_intent_analysis
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEFAULT_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro")

SYSTEM_PROMPT = """You are a senior vulnerability research engineer.
You will receive one JSON object with these fields:
- `project`
- `cve_id`
- `cwe`
- `vulnerability_description`
- `patch_commit_title`
- `patch_commit_message`
- `patch_hunk` (old/new lines)
- `reduced_function_code` (patch-focused function context)

Your job is to produce a high-confidence vulnerability explanation based on this evidence.

## What to do

### 1) Root Cause Analysis
Provide:
- `summary`: concise root-cause statement
- `unsafe_mechanism`: exact unsafe mechanism in pre-patch behavior

### 2) Patch Intent Analysis
Provide:
- `summary`: concise patch-intent statement
- `intended_security_property`: what security property the patch enforces
- `behavior_changes`: concrete behavior-level changes from old -> new

## Critical reasoning rules
1. Treat `patch_hunk.old_lines` as pre-patch evidence and `patch_hunk.new_lines` as post-patch evidence.
2. Do not confuse post-patch details with root cause unless directly evidenced by old lines.
3. Prioritize `patch_hunk` and `patch_commit_message` over generic assumptions.
4. If a claim is not directly evidenced, phrase it as a cautious inference.
5. Be concise and technical; do not repeat input fields verbatim.

## Output format (STRICT)
Return exactly this JSON object shape:

{
  "root_cause_analysis": {
    "summary": "",
    "unsafe_mechanism": ""
  },
  "patch_intent_analysis": {
    "summary": "",
    "intended_security_property": "",
    "behavior_changes": []
  }
}
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate CVE behavior analysis metadata with DeepSeek.")
    parser.add_argument("--input", required=True, type=Path, help="Compact project metadata JSON.")
    parser.add_argument("--output", required=True, type=Path, help="Output JSON with behavior analysis fields.")
    parser.add_argument("--cve", action="append", default=[], help="Optional CVE filter; repeatable.")
    parser.add_argument("--limit", type=int, default=0, help="Optional max CVEs to process.")
    parser.add_argument("--resume", action="store_true", help="Reuse existing analyzed CVEs from --output.")
    parser.add_argument("--model", default="", help=f"Defaults to DEEPSEEK_MODEL or {DEFAULT_MODEL}.")
    parser.add_argument("--base-url", default="", help=f"Defaults to DEEPSEEK_BASE_URL or {DEFAULT_BASE_URL}.")
    parser.add_argument("--env-file", default="", help="Optional .env file with DEEPSEEK_API_KEY=... .")
    parser.add_argument("--api-timeout", type=int, default=300)
    parser.add_argument("--sleep", type=float, default=0.0, help="Delay between API calls.")
    parser.add_argument("--dry-run", action="store_true", help="Print first prompt payload and exit.")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def load_env_file(path: Path) -> dict[str, str]:
    loaded: dict[str, str] = {}
    if not path.is_file():
        return loaded
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
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
            loaded[key] = value
    return loaded


def load_default_env_files(extra_env_file: str = "") -> None:
    candidates = [ROOT / ".env"]
    if extra_env_file:
        candidates.append(Path(extra_env_file).expanduser())
    for path in candidates:
        load_env_file(path)


def import_env_from_interactive_shell(keys: list[str]) -> None:
    missing = [key for key in keys if not os.environ.get(key)]
    if not missing:
        return
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
        return
    if proc.returncode != 0:
        return
    try:
        data = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        return
    for key, value in data.items():
        if value and not os.environ.get(key):
            os.environ[key] = value


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"expected JSON object: {path}")
    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    tmp.replace(path)


def selected_items(data: dict[str, Any], cves: list[str], limit: int) -> list[tuple[str, dict[str, Any]]]:
    wanted = set(cves) if cves else None
    out: list[tuple[str, dict[str, Any]]] = []
    for cve_id in sorted(data):
        if wanted and cve_id not in wanted:
            continue
        item = data[cve_id]
        if not isinstance(item, dict):
            continue
        out.append((cve_id, item))
        if limit and len(out) >= limit:
            break
    return out


def cve_payload(cve_id: str, item: dict[str, Any]) -> dict[str, Any]:
    payload = dict(item)
    payload.setdefault("cve_id", cve_id)
    return payload


def deepseek_chat(
    messages: list[dict[str, Any]],
    *,
    api_key: str,
    base_url: str,
    model: str,
    timeout: int,
) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"DeepSeek HTTP {exc.code}: {body}") from exc


def extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise
        data = json.loads(text[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("model output is not a JSON object")
    return data


def validate_analysis(data: dict[str, Any]) -> dict[str, Any]:
    root = data.get("root_cause_analysis")
    intent = data.get("patch_intent_analysis")
    if not isinstance(root, dict) or not isinstance(intent, dict):
        raise ValueError("missing root_cause_analysis or patch_intent_analysis")
    behavior = intent.get("behavior_changes")
    if not isinstance(behavior, list) or not all(isinstance(x, str) for x in behavior):
        raise ValueError("patch_intent_analysis.behavior_changes must be a string list")
    return {
        "root_cause_analysis": {
            "summary": str(root.get("summary", "")).strip(),
            "unsafe_mechanism": str(root.get("unsafe_mechanism", "")).strip(),
        },
        "patch_intent_analysis": {
            "summary": str(intent.get("summary", "")).strip(),
            "intended_security_property": str(intent.get("intended_security_property", "")).strip(),
            "behavior_changes": [x.strip() for x in behavior if x.strip()],
        },
    }


def analyze_one(
    cve_id: str,
    item: dict[str, Any],
    *,
    api_key: str,
    base_url: str,
    model: str,
    timeout: int,
    verbose: bool,
) -> dict[str, Any]:
    payload = cve_payload(cve_id, item)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Now analyze this input JSON:\n" + json.dumps(payload, indent=2, ensure_ascii=False)},
    ]
    resp = deepseek_chat(messages, api_key=api_key, base_url=base_url, model=model, timeout=timeout)
    message = resp["choices"][0]["message"]
    content = message.get("content") or ""
    if verbose and message.get("reasoning_content"):
        print(f"[{cve_id}] reasoning_content chars={len(message.get('reasoning_content') or '')}")
    return validate_analysis(extract_json_object(content))


def main() -> int:
    args = parse_args()
    source = load_json(args.input)
    existing = load_json(args.output) if args.resume and args.output.exists() else {}
    output = dict(existing) if args.resume else {}
    items = selected_items(source, args.cve, args.limit)
    if not items:
        raise SystemExit("no CVEs selected")

    if args.dry_run:
        cve_id, item = items[0]
        print(SYSTEM_PROMPT)
        print("Now analyze this input JSON:")
        print(json.dumps(cve_payload(cve_id, item), indent=2, ensure_ascii=False))
        return 0

    load_default_env_files(args.env_file)
    import_env_from_interactive_shell(["DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL"])
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise SystemExit("DEEPSEEK_API_KEY is not set")
    base_url = args.base_url or os.environ.get("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL)
    model = args.model or os.environ.get("DEEPSEEK_MODEL", DEFAULT_MODEL)

    for index, (cve_id, item) in enumerate(items, 1):
        if args.resume and cve_id in output:
            existing_item = output[cve_id]
            if isinstance(existing_item, dict) and existing_item.get("root_cause_analysis") and existing_item.get("patch_intent_analysis"):
                print(f"[{index}/{len(items)}] skip {cve_id}")
                continue
        print(f"[{index}/{len(items)}] analyze {cve_id}")
        enriched = dict(item)
        try:
            analysis = analyze_one(
                cve_id,
                item,
                api_key=api_key,
                base_url=base_url,
                model=model,
                timeout=args.api_timeout,
                verbose=args.verbose,
            )
            enriched.update(analysis)
        except Exception as exc:
            enriched["behavior_analysis_error"] = repr(exc)
        output[cve_id] = enriched
        write_json(args.output, output)
        if args.sleep:
            time.sleep(args.sleep)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
