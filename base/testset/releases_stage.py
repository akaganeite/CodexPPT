from __future__ import annotations

import re
import subprocess
from pathlib import Path

from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger
from utils.io import read_json
from utils.paths import ROOT


def project_tag_rule(project: str) -> dict:
    config = read_json(ROOT / "config.json", {})
    rule = (config.get("tag_rules", {}) or {}).get(project, {})
    return rule if isinstance(rule, dict) else {}


def normalize_tag(tag: str, rule: dict) -> str:
    pattern = rule.get("tag_pattern")
    if not pattern:
        return tag if re.search(r"\d", tag) else ""
    match = re.match(pattern, tag)
    if not match:
        return ""
    groups = [group for group in match.groups() if group]
    version = groups[0] if groups else match.group(0)
    replace = rule.get("replace", {}) or {}
    if isinstance(replace, dict):
        for old, new in replace.items():
            version = version.replace(str(old), str(new))
    return version


def tag_date(repo: Path, tag: str) -> tuple[str, str]:
    sha = subprocess.run(["git", "-C", str(repo), "rev-list", "-n", "1", tag], stdout=subprocess.PIPE, text=True, check=True).stdout.strip()
    date = subprocess.run(["git", "-C", str(repo), "show", "-s", "--format=%ci", sha], stdout=subprocess.PIPE, text=True, check=True).stdout.strip()
    return sha, date[:19]


def update_releases(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "releases")
    rule = project_tag_rule(config.project)
    tags = subprocess.run(["git", "-C", str(config.repo), "tag"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True).stdout.splitlines()
    count = 0
    for tag in tags:
        norm = normalize_tag(tag, rule)
        if not norm or not re.search(r"\d", norm):
            continue
        try:
            sha, date = tag_date(config.repo, tag)
        except Exception as exc:
            log.warn("failed to parse tag", tag=tag, error=str(exc))
            continue
        db.upsert_release({"tag": tag, "commit_sha": sha, "date": date, "version": norm, "norm_tag": norm})
        count += 1
    db.record_stage("releases", "ok", {"count": count, "tag_rule": rule})
    log.trace("releases updated", count=count, tag_rule=rule)
