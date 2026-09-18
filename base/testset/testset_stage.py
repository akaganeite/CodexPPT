from __future__ import annotations

from CVEhunt.nvd_constraints import affected_constraints

import re
import subprocess
from datetime import datetime

from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger


TESTSET_AFFECTED_FILTER = "nvd-configurations"


def commit_date(repo, commit: str) -> datetime | None:
    proc = subprocess.run(["git", "-C", str(repo), "show", "-s", "--format=%ci", commit], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if proc.returncode:
        return None
    return datetime.strptime(proc.stdout.strip()[:19], "%Y-%m-%d %H:%M:%S")


def tag_contains(repo, tag: str, commit: str) -> bool:
    proc = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, tag], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    return proc.returncode == 0


def release_date(row) -> datetime | None:
    try:
        return datetime.strptime(row["date"][:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def is_stable_release(row) -> bool:
    version = (row["version"] or row["norm_tag"] or row["tag"] or "").lower()
    tag = (row["tag"] or "").lower()
    unstable_tokens = (
        "alpha",
        "beta",
        "pre",
        "rc",
        "dev",
        "snapshot",
        "post-reformat",
        "post-auto-reformat",
        "auto-reformat",
        "reformat",
    )
    return not any(token in version or token in tag for token in unstable_tokens)


def release_branch(version: str) -> str:
    version = version.lower().replace("_", ".").replace("-", ".")
    numeric = re.findall(r"\d+", version)
    if not numeric:
        return version
    if re.fullmatch(r"\d+\.\d+\.\d+[a-z]+", version) and len(numeric) >= 3:
        return ".".join(numeric[:3])
    if len(numeric) >= 2:
        return ".".join(numeric[:2])
    return numeric[0]


def version_token_key(version: str) -> tuple:
    version = version.lower().replace("_", ".").replace("-", ".")
    tokens = re.findall(r"\d+|[a-z]+", version)
    out = []
    for token in tokens:
        if token.isdigit():
            out.append((0, int(token)))
        else:
            out.append((1, token))
    return tuple(out)


def version_compare(left: str, right: str) -> int:
    left_key = version_token_key(left)
    right_key = version_token_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def normalize_version_text(version: str) -> str:
    return version.lower().replace("_", ".").replace("-", ".").strip()


def stable_releases(db: ProjectDB, log) -> list:
    all_releases = db.releases()
    releases = [row for row in all_releases if is_stable_release(row)]
    skipped = len(all_releases) - len(releases)
    if skipped:
        log.trace("ignored prerelease tags for default testset", count=skipped)
    return releases


def selected_reuse_ok(config: BuildConfig, db: ProjectDB) -> bool:
    previous = db.latest_stage_detail("testset")
    return (
        previous.get("strategy") == config.testset_strategy
        and int(previous.get("count", 0) or 0) == config.testset_count
        and previous.get("affected_filter") == TESTSET_AFFECTED_FILTER
    )


def iter_refs_for_selection(config: BuildConfig, db: ProjectDB, log, refs: list):
    reuse_existing = selected_reuse_ok(config, db)
    for ref in refs:
        cve_id = ref["cve_id"]
        existing = db.conn.execute(
            "SELECT 1 FROM testset_entries WHERE cve_id=? LIMIT 1",
            (cve_id,),
        ).fetchone()
        if existing and reuse_existing:
            log.trace("reuse selected testset", cve=cve_id)
            continue
        patch_commit = ref["patch_commit"]
        pdate = commit_date(config.repo, patch_commit)
        if not pdate:
            log.warn("missing patch commit date", cve=cve_id, commit=patch_commit)
            continue
        yield ref, cve_id, patch_commit, pdate


def release_item(rel, ref) -> dict:
    version = rel["norm_tag"]
    return {
        "version": version,
        "tag": rel["tag"],
        "binary_name": ref["binary_name"],
        "branch": release_branch(version),
    }


def split_releases_by_patch_date(releases: list, ref, pdate: datetime) -> tuple[list[tuple[int, dict]], list[tuple[int, dict]]]:
    before = []
    after = []
    for rel in releases:
        rdate = release_date(rel)
        if not rdate:
            continue
        item = release_item(rel, ref)
        distance = abs((pdate - rdate).days)
        if rdate < pdate:
            before.append((distance, item))
        else:
            after.append((distance, item))
    before.sort(key=lambda x: x[0])
    after.sort(key=lambda x: x[0])
    return before, after




def version_matches_constraint(version: str, constraint: dict) -> bool:
    if constraint.get("all"):
        return True
    exact = constraint.get("exact") or ""
    if exact:
        return normalize_version_text(version) == normalize_version_text(exact)
    start_including = constraint.get("start_including") or ""
    start_excluding = constraint.get("start_excluding") or ""
    end_including = constraint.get("end_including") or ""
    end_excluding = constraint.get("end_excluding") or ""
    if start_including and version_compare(version, start_including) < 0:
        return False
    if start_excluding and version_compare(version, start_excluding) <= 0:
        return False
    if end_including and version_compare(version, end_including) > 0:
        return False
    if end_excluding and version_compare(version, end_excluding) >= 0:
        return False
    return any((start_including, start_excluding, end_including, end_excluding))


def version_is_affected(version: str, constraints: list[dict]) -> bool:
    return any(version_matches_constraint(version, constraint) for constraint in constraints)


def filter_affected_vuln_candidates(config: BuildConfig, db: ProjectDB, log, cve_id: str, before: list[tuple[int, dict]]) -> list[tuple[int, dict]]:
    constraints = affected_constraints(config, db, cve_id)
    if constraints is None:
        log.trace("no affected version constraints parsed; using chronological vuln candidates", cve=cve_id)
        return before
    affected = [(distance, item) for distance, item in before if version_is_affected(item["version"], constraints)]
    if len(affected) < config.testset_count:
        log.warn(
            "affected versions below requested testset count",
            cve=cve_id,
            requested=config.testset_count,
            affected_candidates=len(affected),
            available_before_candidates=len(before),
        )
    return affected


def bucket_pick(items: list[tuple[int, dict]], count: int) -> list[tuple[int, dict]]:
    if count <= 0 or not items:
        return []
    if len(items) <= count:
        return items[:]
    if count == 1:
        return [items[0]]
    indexes = [round(i * (len(items) - 1) / (count - 1)) for i in range(count)]
    picks = []
    used: set[int] = set()
    for index in indexes:
        while index in used and index + 1 < len(items):
            index += 1
        while index in used and index > 0:
            index -= 1
        if index in used:
            continue
        used.add(index)
        picks.append(items[index])
    cursor = 0
    while len(picks) < count and cursor < len(items):
        if cursor not in used:
            used.add(cursor)
            picks.append(items[cursor])
        cursor += 1
    return picks


def patch_candidates(config: BuildConfig, cve_id: str, patch_commit: str, after: list[tuple[int, dict]], log, suspicious_limit: int) -> tuple[list[tuple[int, dict]], list[dict]]:
    selected = []
    suspicious = []
    for distance, item in after:
        if tag_contains(config.repo, item["tag"], patch_commit):
            selected.append((distance, item))
            continue
        if len(suspicious) < suspicious_limit:
            log.warn("patch candidate missing fix commit", cve=cve_id, tag=item["tag"], commit=patch_commit)
            suspicious.append(
                {
                    **item,
                    "label": "patch",
                    "reason": "release after patch date but does not contain selected fix commit; supplemented next patch candidate",
                    "status": "gt_suspicious",
                }
            )
    return selected, suspicious


def select_chronical_entries(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "testset")
    releases = stable_releases(db, log)
    refs = db.references(config)
    for ref, cve_id, patch_commit, pdate in iter_refs_for_selection(config, db, log, refs):
        before, after = split_releases_by_patch_date(releases, ref, pdate)
        before = filter_affected_vuln_candidates(config, db, log, cve_id, before)
        entries = [
            {**item, "label": "vuln", "reason": "nearest release before patch commit date"}
            for _, item in before[: config.testset_count]
        ]
        selected_patch, suspicious = patch_candidates(config, cve_id, patch_commit, after, log, config.testset_count)
        entries.extend(suspicious)
        entries.extend({**item, "label": "patch", "reason": "nearest release after patch commit date", "status": "selected"} for _, item in selected_patch[: config.testset_count])
        db.replace_testset_entries(cve_id, entries)
        log.trace("testset selected", cve=cve_id, entries=entries)
    db.record_stage("testset", "ok", {"references": len(refs), "strategy": config.testset_strategy, "count": config.testset_count, "affected_filter": TESTSET_AFFECTED_FILTER})


def select_branch_aware_entries(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "testset")
    releases = stable_releases(db, log)
    refs = db.references(config)
    for ref, cve_id, patch_commit, pdate in iter_refs_for_selection(config, db, log, refs):
        before, after = split_releases_by_patch_date(releases, ref, pdate)
        before = filter_affected_vuln_candidates(config, db, log, cve_id, before)
        selected_patch, suspicious = patch_candidates(config, cve_id, patch_commit, after, log, config.testset_count)
        branch_first: list[tuple[int, dict]] = []
        used_branches: set[str] = set()
        used_patch_tags: set[str] = set()
        for candidate in selected_patch:
            branch = candidate[1].get("branch", "")
            if branch in used_branches:
                continue
            used_branches.add(branch)
            used_patch_tags.add(candidate[1]["tag"])
            branch_first.append(candidate)
            if len(branch_first) >= config.testset_count:
                break
        for candidate in selected_patch:
            if len(branch_first) >= config.testset_count:
                break
            if candidate[1]["tag"] in used_patch_tags:
                continue
            used_patch_tags.add(candidate[1]["tag"])
            branch_first.append(candidate)
        patch_entries = [
            {**item, "label": "patch", "reason": "branch-aware release after patch commit date", "status": "selected"}
            for _, item in branch_first
        ]

        patch_branches = {item["branch"] for item in patch_entries}
        preferred_before = [candidate for candidate in before if candidate[1].get("branch", "") in patch_branches]
        fallback_before = [candidate for candidate in before if candidate[1].get("branch", "") not in patch_branches]
        vuln_entries = []
        used_vuln_tags: set[str] = set()
        for _, item in preferred_before + fallback_before:
            if item["tag"] in used_vuln_tags:
                continue
            reason = "nearest same-branch release before patch commit date" if item.get("branch", "") in patch_branches else "nearest fallback release before patch commit date"
            vuln_entries.append({**item, "label": "vuln", "reason": reason})
            used_vuln_tags.add(item["tag"])
            if len(vuln_entries) >= config.testset_count:
                break
        if len(patch_entries) < config.testset_count:
            log.warn("branch-aware patch entries below requested count", cve=cve_id, requested=config.testset_count, selected=len(patch_entries))
        if len(vuln_entries) < config.testset_count:
            log.warn("branch-aware vuln entries below requested count", cve=cve_id, requested=config.testset_count, selected=len(vuln_entries))
        entries = suspicious + vuln_entries + patch_entries
        db.replace_testset_entries(cve_id, entries)
        log.trace("testset selected", cve=cve_id, entries=entries)
    db.record_stage("testset", "ok", {"references": len(refs), "strategy": config.testset_strategy, "count": config.testset_count, "affected_filter": TESTSET_AFFECTED_FILTER})


def select_time_bucket_entries(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "testset")
    releases = stable_releases(db, log)
    refs = db.references(config)
    for ref, cve_id, patch_commit, pdate in iter_refs_for_selection(config, db, log, refs):
        before, after = split_releases_by_patch_date(releases, ref, pdate)
        before = filter_affected_vuln_candidates(config, db, log, cve_id, before)
        entries = [
            {**item, "label": "vuln", "reason": "time-bucket release before patch commit date"}
            for _, item in bucket_pick(before, config.testset_count)
        ]
        selected_patch, suspicious = patch_candidates(config, cve_id, patch_commit, after, log, config.testset_count)
        entries = suspicious + entries
        entries.extend(
            {**item, "label": "patch", "reason": "time-bucket release after patch commit date", "status": "selected"}
            for _, item in bucket_pick(selected_patch, config.testset_count)
        )
        db.replace_testset_entries(cve_id, entries)
        log.trace("testset selected", cve=cve_id, entries=entries)
    db.record_stage("testset", "ok", {"references": len(refs), "strategy": config.testset_strategy, "count": config.testset_count, "affected_filter": TESTSET_AFFECTED_FILTER})


TESTSET_STRATEGIES = {
    "chronical": select_chronical_entries,
    "branch-aware": select_branch_aware_entries,
    "time-bucket": select_time_bucket_entries,
}


def select_default_entries(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "testset")
    strategy = TESTSET_STRATEGIES.get(config.testset_strategy)
    if not strategy:
        supported = sorted(TESTSET_STRATEGIES)
        raise ValueError(f"unsupported testset strategy {config.testset_strategy!r}; supported={supported}")
    log.trace("testset strategy selected", strategy=config.testset_strategy, count=config.testset_count)
    strategy(config, db)
