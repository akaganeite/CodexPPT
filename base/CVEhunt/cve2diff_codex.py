from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger
from utils.codex_exec import run_codex_exec_json
from utils.io import write_text
from utils.paths import ROOT


SCHEMA = ROOT / "schemas" / "cve2diff_result.schema.json"


def fetch_reference_snapshots(urls: list[str], limit: int = 6) -> list[dict[str, str]]:
    snapshots: list[dict[str, str]] = []
    for url in urls[:limit]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "agentic-dataset-builder/0.1"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read(250_000).decode("utf-8", errors="replace")
            text = re.sub(r"<script.*?</script>", " ", raw, flags=re.S | re.I)
            text = re.sub(r"<style.*?</style>", " ", text, flags=re.S | re.I)
            text = re.sub(r"<[^>]+>", " ", text)
            text = re.sub(r"\s+", " ", text).strip()
            snapshots.append({"url": url, "text": text[:20000]})
        except Exception as exc:
            snapshots.append({"url": url, "text": f"FETCH_FAILED: {exc}"})
    return snapshots


def render_prompt(cve: dict[str, Any], repo: Path, snapshots: list[dict[str, str]]) -> str:
    return f"""Find the canonical fix commit for this CVE in the local project repository.

Inputs:
- Local git repo: {repo}
- CVE: {cve['cve_id']}
- Summary: {cve.get('summary', '')}
- References: {json.loads(cve.get('references_json') or '[]')}
- Reference page snapshots:
{json.dumps(snapshots, ensure_ascii=False, indent=2)[:90000]}

Task:
1. Inspect the reference snapshots and the local git repository.
2. Use git log --all --grep, git log -G, git show, and date/window evidence as needed.
3. Return candidate fix commits. Select exactly one canonical commit when possible.
4. Prefer mainline fix over backport, then confidence, then earliest real fix date.
5. Do not invent commits. Every commit must exist in the local repo.

Return JSON only according to the schema.
"""


def git(repo: Path, args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=check,
    )


def verify_commit(repo: Path, commit: str) -> tuple[bool, str]:
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", commit or ""):
        return False, "invalid commit shape"
    proc = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{commit}^{{commit}}"], check=False)
    if proc.returncode:
        return False, "commit not found"
    parent = git(repo, ["rev-parse", f"{commit}^"], check=False)
    if parent.returncode:
        return False, "parent not found"
    return True, parent.stdout.strip()


def write_diff_and_patch_id(config: BuildConfig, cve_id: str, commit: str) -> tuple[str, str]:
    config.diff_dir.mkdir(parents=True, exist_ok=True)
    diff_path = config.diff_dir / f"{config.project}_{cve_id}_{commit[:12]}.diff"
    diff = git(config.repo, ["show", "--format=fuller", "--patch", commit]).stdout
    write_text(diff_path, diff)
    patch_proc = subprocess.run(
        ["git", "-C", str(config.repo), "show", "--format=", "--patch", commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    patch_id_proc = subprocess.run(
        ["git", "patch-id", "--stable"],
        input=patch_proc.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    patch_id = patch_id_proc.stdout.split()[0] if patch_id_proc.stdout.split() else ""
    return str(diff_path), patch_id


def choose_candidate(result: dict[str, Any]) -> dict[str, Any] | None:
    candidates = result.get("candidates", [])
    selected = [c for c in candidates if c.get("selected")]
    if selected:
        return selected[0]
    selected_commit = result.get("selected_commit", "")
    for candidate in candidates:
        if candidate.get("commit", "").startswith(selected_commit) or selected_commit.startswith(candidate.get("commit", "")):
            return candidate
    if candidates:
        relation_rank = {"mainline": 0, "backport": 1, "patch_evolution": 2, "unknown": 3}
        return sorted(candidates, key=lambda c: (relation_rank.get(c.get("relation", "unknown"), 9), -float(c.get("confidence", 0))))[0]
    return None


def candidate_commits_from_reference_url(url: str) -> list[str]:
    patterns = [
        r"/commit/([0-9a-fA-F]{7,40})(?:[/?#.]|$)",
        r"/commits/([0-9a-fA-F]{7,40})(?:[/?#.]|$)",
        r"/-/commit/([0-9a-fA-F]{7,40})(?:[/?#.]|$)",
        r"[?&;]id=([0-9a-fA-F]{7,40})(?:[&#;]|$)",
        r"[?&;]h=([0-9a-fA-F]{7,40})(?:[&#;]|$)",
        r"[?&;]commit=([0-9a-fA-F]{7,40})(?:[&#;]|$)",
    ]
    commits: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        for match in re.finditer(pattern, url):
            commit = match.group(1)
            if commit.lower() in seen:
                continue
            seen.add(commit.lower())
            commits.append(commit)
    return commits


def extract_direct_commit_candidates(row: Any, repo: Path) -> list[dict[str, Any]]:
    refs = json.loads(row["references_json"] or "[]")
    candidates = []
    seen = set()
    for url in refs:
        for commit in candidate_commits_from_reference_url(url):
            if commit.lower() in seen:
                continue
            seen.add(commit.lower())
            ok, parent = verify_commit(repo, commit)
            if not ok:
                continue
            show = git(repo, ["show", "-s", "--format=%B", commit], check=False)
            message = show.stdout if show.returncode == 0 else ""
            relation = "backport" if "cherry picked from commit" in message.lower() else "mainline"
            candidates.append(
                {
                    "commit": commit,
                    "parent": parent,
                    "relation": relation,
                    "confidence": 0.98 if row["cve_id"] in message else 0.9,
                    "source": "direct_reference_url",
                    "evidence": [url, "commit hash found in reference URL", "commit exists in local repo", "commit message checked"],
                    "selected": False,
                    "status": "verified",
                }
            )
    return candidates


def select_direct_candidate(candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not candidates:
        return None
    relation_rank = {"mainline": 0, "backport": 1, "patch_evolution": 2, "unknown": 3}
    return sorted(candidates, key=lambda c: (relation_rank.get(c.get("relation", "unknown"), 9), -float(c.get("confidence", 0))))[0]


def run_cve2diff(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "cve2diff")
    codex_dir = config.codex_dir / "cve2diff"
    codex_dir.mkdir(parents=True, exist_ok=True)
    for row in db.selected_cves(config):
        cve_id = row["cve_id"]
        existing = db.conn.execute(
            "SELECT 1 FROM fix_candidates WHERE cve_id=? AND selected=1",
            (cve_id,),
        ).fetchone()
        if existing:
            log.trace("reuse selected fix commit", cve=cve_id)
            continue
        direct_candidates = extract_direct_commit_candidates(row, config.repo)
        direct_selected = select_direct_candidate(direct_candidates)
        if direct_selected:
            for candidate in direct_candidates:
                candidate["selected"] = candidate["commit"] == direct_selected["commit"]
                diff_path = ""
                patch_id = ""
                if candidate["selected"]:
                    diff_path, patch_id = write_diff_and_patch_id(config, cve_id, candidate["commit"])
                db.upsert_fix_candidate(cve_id, candidate, diff_path=diff_path, patch_id=patch_id)
            log.trace("selected direct fix commit", cve=cve_id, commit=direct_selected["commit"], candidates=len(direct_candidates))
            continue
        output_path = codex_dir / f"{cve_id}.result.json"
        events_path = codex_dir / f"{cve_id}.events.jsonl"
        prompt_path = codex_dir / f"{cve_id}.prompt.md"
        snapshots = fetch_reference_snapshots(json.loads(row["references_json"] or "[]"))
        write_text(prompt_path, render_prompt(dict(row), config.repo, snapshots))
        log.trace("running codex cve2diff", cve=cve_id)
        try:
            result = run_codex_exec_json(
                prompt_path=prompt_path,
                output_path=output_path,
                json_events_path=events_path,
                schema_path=SCHEMA,
                codex_model=config.codex_model,
                codex_sandbox=config.codex_sandbox,
                add_dirs=[config.repo],
                timeout=1800,
            )
        except Exception as exc:
            log.error("codex cve2diff failed", cve=cve_id, error=str(exc))
            continue
        candidate = choose_candidate(result)
        if not candidate:
            log.warn("no cve2diff candidate", cve=cve_id, result=result)
            continue
        ok, parent_or_reason = verify_commit(config.repo, candidate["commit"])
        if not ok:
            log.warn("candidate failed verification", cve=cve_id, commit=candidate.get("commit"), reason=parent_or_reason)
            continue
        candidate["parent"] = candidate.get("parent") or parent_or_reason
        candidate["selected"] = True
        candidate["status"] = "verified"
        diff_path, patch_id = write_diff_and_patch_id(config, cve_id, candidate["commit"])
        db.upsert_fix_candidate(cve_id, candidate, diff_path=diff_path, patch_id=patch_id)
        log.trace("selected fix commit", cve=cve_id, commit=candidate["commit"], diff_path=diff_path)
    db.record_stage("cve2diff", "ok", {})
