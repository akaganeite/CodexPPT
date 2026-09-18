"""Bounded, read-only access to source files changed by a patch commit.

The source repository is a Host-only input.  This module resolves the patch
commit and its allowlisted files through Git's object database, without
checking out a worktree or exposing the repository path or commit id to the
Agent.  Source-tool results are investigation guidance and deliberately do not
create observations or evidence ledger entries.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from claudeagent.responses_client import waf_safe_output


SOURCE_TOOL_NAMES = {
    "list_patch_sources",
    "read_patch_source",
    "search_patch_source",
    "read_patch_function",
}

MAX_SOURCE_FILES = 64
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_TOTAL_CHARS = 32 * 1024 * 1024
MAX_READ_LINES = 200
MAX_READ_CHARS = 13 * 1024
MAX_FUNCTION_LINES = 400
MAX_FUNCTION_CHARS = 13 * 1024
MAX_FUNCTION_CONTEXT_LINES = 50
MAX_SEARCH_RESULTS = 50
MAX_SEARCH_CONTEXT_LINES = 5
MAX_SEARCH_CHARS = 13 * 1024
MAX_QUERY_CHARS = 256
MAX_TOOL_RESULT_CHARS = 16 * 1024
SOURCE_TOOL_CALL_LIMIT = 8
SOURCE_CONTEXT_CHAR_BUDGET = 64 * 1024
GIT_TIMEOUT_SEC = 30
CTAGS_TIMEOUT_SEC = 10
MAX_GIT_STDOUT_BYTES = 24 * 1024 * 1024
MAX_PROCESS_STDERR_BYTES = 256 * 1024
MAX_CTAGS_STDOUT_BYTES = 4 * 1024 * 1024

_COMMIT_RE = re.compile(r"[0-9a-fA-F]{7,64}")
_FULL_OBJECT_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REGULAR_FILE_MODES = {"100644", "100755"}


@dataclass(frozen=True)
class PatchSourceLocation:
    """One metadata-declared changed function and its source coordinates."""

    function: str
    function_line_range: tuple[int, int] | None = None
    changed_old_lines: tuple[int, ...] = ()
    changed_new_lines: tuple[int, ...] = ()

    def agent_entry(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "function_line_range": (
                list(self.function_line_range) if self.function_line_range is not None else []
            ),
            "changed_old_lines": list(self.changed_old_lines),
            "changed_new_lines": list(self.changed_new_lines),
        }


@dataclass(frozen=True)
class _RequestedSourceFile:
    path: str
    locations: tuple[PatchSourceLocation, ...]

    @property
    def functions(self) -> tuple[str, ...]:
        return tuple(location.function for location in self.locations)


@dataclass(frozen=True)
class _GitChange:
    status: str
    change_type: str
    path: str
    old_path: str = ""


@dataclass(frozen=True)
class _BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class _ProcessOutputLimitError(RuntimeError):
    """Raised after terminating a child that exceeds a pipe byte budget."""


def _run_bounded_process(
    argv: list[str],
    *,
    timeout: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int = MAX_PROCESS_STDERR_BYTES,
    env: dict[str, str] | None = None,
) -> _BoundedProcessResult:
    """Run a child while draining both pipes incrementally under hard caps."""
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        bufsize=0,
    )
    assert proc.stdout is not None and proc.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, ("stdout", max_stdout_bytes))
    selector.register(proc.stderr, selectors.EVENT_READ, ("stderr", max_stderr_bytes))
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            events = selector.select(min(remaining, 0.25))
            if not events:
                continue
            for key, _mask in events:
                stream_name, limit = key.data
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[stream_name].extend(chunk)
                if len(buffers[stream_name]) > limit:
                    raise _ProcessOutputLimitError(
                        f"child {stream_name} exceeded the {limit}-byte limit"
                    )
        remaining = max(0.001, deadline - time.monotonic())
        returncode = proc.wait(timeout=remaining)
        return _BoundedProcessResult(
            returncode=returncode,
            stdout=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]),
        )
    except Exception:
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()


@dataclass(frozen=True)
class PatchSourceFile:
    """One immutable, allowlisted blob from the patch commit."""

    source_file_id: str
    path: str
    locations: tuple[PatchSourceLocation, ...]
    change_type: str
    mode: str
    blob_oid: str = field(repr=False)
    content: str = field(default="", repr=False)
    lines: tuple[str, ...] = field(default=(), repr=False)

    @property
    def functions(self) -> tuple[str, ...]:
        return tuple(location.function for location in self.locations)

    def location_for_function(self, function_name: str) -> PatchSourceLocation | None:
        return next((location for location in self.locations if location.function == function_name), None)

    def agent_entry(self) -> dict[str, Any]:
        """Return the safe subset that may be shown to the Agent."""
        return {
            "source_file_id": self.source_file_id,
            "path": self.path,
            "functions": list(self.functions),
            "locations": [location.agent_entry() for location in self.locations],
            "change_type": self.change_type,
        }


@dataclass(frozen=True)
class PatchSourceContext:
    """Host-owned immutable view of patch-after source blobs."""

    source_repo: Path = field(repr=False)
    commit_oid: str = field(repr=False)
    files: tuple[PatchSourceFile, ...]
    source_context_sha256: str

    def agent_manifest(self) -> dict[str, Any]:
        """Return an Agent-safe manifest with no Host path or commit identity."""
        return {
            "available": True,
            "files": [source_file.agent_entry() for source_file in self.files],
            "limits": {
                "read_max_lines": MAX_READ_LINES,
                "read_max_chars": MAX_READ_CHARS,
                "function_max_lines": MAX_FUNCTION_LINES,
                "function_max_chars": MAX_FUNCTION_CHARS,
                "search_max_results": MAX_SEARCH_RESULTS,
            },
        }

    def file_for_id(self, source_file_id: str) -> PatchSourceFile | None:
        for source_file in self.files:
            if source_file.source_file_id == source_file_id:
                return source_file
        return None


_PATCH_SOURCE_CONTEXT: PatchSourceContext | None = None
_PATCH_SOURCE_TOOL_CALL_COUNT = 0
_PATCH_SOURCE_RETURNED_CHARS = 0


def set_patch_source_context(context: PatchSourceContext | None) -> None:
    """Set or clear the patch-source view used by source tool functions."""
    global _PATCH_SOURCE_CONTEXT, _PATCH_SOURCE_TOOL_CALL_COUNT, _PATCH_SOURCE_RETURNED_CHARS
    if context is not None and not isinstance(context, PatchSourceContext):
        raise TypeError("patch source context must be PatchSourceContext or None")
    _PATCH_SOURCE_CONTEXT = context
    _PATCH_SOURCE_TOOL_CALL_COUNT = 0
    _PATCH_SOURCE_RETURNED_CHARS = 0


def _safe_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("patch source file path must be a non-empty string")
    if len(value) > 1024 or "\x00" in value or "\n" in value or "\r" in value or "\\" in value:
        raise ValueError("patch source file path contains forbidden characters")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("patch source file path must be a normalized repo-relative path")
    if path.as_posix() != value:
        raise ValueError("patch source file path must be normalized")
    return value


def _safe_function_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("patch source function name must be a non-empty string")
    if len(value) > 512 or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("patch source function name is invalid")
    return value.strip()


def _parse_line_range(value: Any, label: str) -> tuple[int, int] | None:
    if value == [] or value is None:
        return None
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(not isinstance(item, int) or isinstance(item, bool) for item in value)
        or value[0] < 1
        or value[0] > value[1]
    ):
        raise ValueError(f"{label} must be an empty list or [positive_start, positive_end]")
    return value[0], value[1]


def _parse_line_list(value: Any, label: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list of positive line numbers")
    if any(not isinstance(item, int) or isinstance(item, bool) or item < 1 for item in value):
        raise ValueError(f"{label} must contain positive line numbers")
    parsed = tuple(value)
    if parsed != tuple(sorted(set(parsed))):
        raise ValueError(f"{label} must be sorted and contain no duplicates")
    return parsed


def _parse_patch_source_metadata(
    metadata: Any,
) -> tuple[str, list[_RequestedSourceFile]] | None:
    """Parse the locations-only source allowlist, or disable source access."""
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")

    patch_source = metadata.get("patch_source")
    if patch_source is None:
        return None
    if not isinstance(patch_source, dict):
        raise ValueError("metadata patch_source must be an object")
    if "files" in patch_source:
        raise ValueError("patch_source.files is unsupported; use patch_source.locations")
    locations = patch_source.get("locations")
    if locations is None or locations == []:
        return None
    if not isinstance(locations, list):
        raise ValueError("metadata patch_source.locations must be a list")
    commit = patch_source.get("commit")

    if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit):
        raise ValueError("patch source commit must be a 7-64 character hexadecimal object id")
    grouped: dict[str, list[PatchSourceLocation]] = {}
    seen: set[tuple[str, str]] = set()
    required_keys = {
        "function",
        "file",
        "function_line_range",
        "changed_old_lines",
        "changed_new_lines",
    }
    for entry in locations:
        if not isinstance(entry, dict) or set(entry) != required_keys:
            raise ValueError("each patch_source location must contain exactly the required location fields")
        path = _safe_relative_path(entry.get("file"))
        function = _safe_function_name(entry.get("function"))
        identifier = path, function
        if identifier in seen:
            raise ValueError("patch_source locations must not duplicate a file/function pair")
        seen.add(identifier)
        grouped.setdefault(path, []).append(PatchSourceLocation(
            function=function,
            function_line_range=_parse_line_range(
                entry.get("function_line_range"), "patch_source function_line_range"
            ),
            changed_old_lines=_parse_line_list(
                entry.get("changed_old_lines"), "patch_source changed_old_lines"
            ),
            changed_new_lines=_parse_line_list(
                entry.get("changed_new_lines"), "patch_source changed_new_lines"
            ),
        ))
    if len(grouped) > MAX_SOURCE_FILES:
        raise ValueError(f"patch source metadata exceeds the {MAX_SOURCE_FILES}-file limit")
    requested = [
        _RequestedSourceFile(path=path, locations=tuple(sorted(locations, key=lambda item: item.function)))
        for path, locations in sorted(grouped.items())
    ]
    return commit, requested


def _git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_EXEC_PATH",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
    ):
        environment.pop(key, None)
    for key in list(environment):
        if key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment["GIT_CONFIG_COUNT"] = "0"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_PAGER"] = "cat"
    environment["LC_ALL"] = "C"
    return environment


def _run_git(
    source_repo: Path,
    args: list[str],
    *,
    action: str,
    max_stdout_bytes: int = MAX_GIT_STDOUT_BYTES,
) -> bytes:
    # Source repositories can live on a mounted dataset owned by another UID.
    # A caller may pass a component subdirectory (e.g. binutils-gdb/binutils),
    # while Git identifies the parent worktree as the repository. Trust only
    # the supplied path and its nearest enclosing Git worktree for this one
    # invocation; all ambient Git configuration remains cleared below.
    safe_dirs = [source_repo]
    for candidate in source_repo.parents:
        if (candidate / ".git").exists():
            safe_dirs.append(candidate)
            break
    safe_args = [item for directory in dict.fromkeys(safe_dirs) for item in ("-c", f"safe.directory={directory}")]
    try:
        proc = _run_bounded_process(
            ["git", *safe_args, "-C", str(source_repo), *args],
            timeout=GIT_TIMEOUT_SEC,
            max_stdout_bytes=max_stdout_bytes,
            env=_git_environment(),
        )
    except FileNotFoundError as exc:
        raise ValueError("git executable is unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"git timed out while attempting to {action}") from exc
    except _ProcessOutputLimitError as exc:
        raise ValueError(f"git output exceeded the limit while attempting to {action}") from exc
    if proc.returncode != 0:
        raise ValueError(f"git failed to {action}")
    return proc.stdout


def _parse_changed_files(raw: bytes) -> dict[str, _GitChange]:
    parts = raw.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    changes: dict[str, _GitChange] = {}
    index = 0
    while index < len(parts):
        try:
            status = parts[index].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("git diff-tree returned an invalid change status") from exc
        index += 1
        status_code = status[:1]
        if status_code in {"R", "C"}:
            if index + 1 >= len(parts):
                raise ValueError("git diff-tree returned a malformed rename/copy record")
            try:
                old_path = parts[index].decode("utf-8")
                path = parts[index + 1].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("patch commit contains a non-UTF-8 file path") from exc
            index += 2
        else:
            if status_code not in {"A", "D", "M", "T"} or index >= len(parts):
                raise ValueError("git diff-tree returned an unsupported change record")
            try:
                path = parts[index].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("patch commit contains a non-UTF-8 file path") from exc
            old_path = ""
            index += 1
        change_type = {
            "A": "added",
            "C": "copied",
            "D": "deleted",
            "M": "modified",
            "R": "renamed",
            "T": "type_changed",
        }[status_code]
        if path in changes and changes[path] != _GitChange(status, change_type, path, old_path):
            raise ValueError("patch commit contains ambiguous changes for an allowlisted path")
        changes[path] = _GitChange(status, change_type, path, old_path)
    return changes


def _ls_tree_blob(source_repo: Path, commit_oid: str, path: str) -> tuple[str, str]:
    raw = _run_git(
        source_repo,
        ["ls-tree", "-z", "--full-tree", commit_oid, "--", path],
        action="resolve a patch source file",
    )
    records = [record for record in raw.split(b"\x00") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise ValueError(f"patch source file is absent after the patch: {path}")
    header, raw_output_path = records[0].split(b"\t", 1)
    try:
        mode, object_type, blob_oid = header.decode("ascii").split(" ", 2)
        output_path = raw_output_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("git ls-tree returned a malformed source entry") from exc
    if output_path != path:
        raise ValueError(f"git resolved an unexpected patch source path for: {path}")
    if mode == "120000":
        raise ValueError(f"patch source path is a symlink and is not allowed: {path}")
    if mode == "160000" or object_type == "commit":
        raise ValueError(f"patch source path is a submodule and is not allowed: {path}")
    if mode not in _REGULAR_FILE_MODES or object_type != "blob" or not _FULL_OBJECT_RE.fullmatch(blob_oid):
        raise ValueError(f"patch source path is not a regular file: {path}")
    return mode, blob_oid


def _read_blob(source_repo: Path, blob_oid: str, path: str) -> str:
    raw_size = _run_git(source_repo, ["cat-file", "-s", blob_oid], action="measure a patch source blob")
    try:
        size = int(raw_size.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("git cat-file returned an invalid blob size") from exc
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"patch source file exceeds the {MAX_SOURCE_BYTES}-byte limit: {path}")
    raw = _run_git(
        source_repo,
        ["cat-file", "blob", blob_oid],
        action="read a patch source blob",
        max_stdout_bytes=MAX_SOURCE_BYTES,
    )
    if len(raw) != size:
        raise ValueError("git returned an incomplete patch source blob")
    if b"\x00" in raw:
        raise ValueError(f"patch source path is not a text file: {path}")
    return raw.decode("utf-8", errors="replace")


def build_patch_source_context(
    source_repo: str | os.PathLike[str], metadata: dict[str, Any]
) -> PatchSourceContext | None:
    """Build an immutable patch-after source view from metadata and Git objects."""
    parsed_metadata = _parse_patch_source_metadata(metadata)
    if parsed_metadata is None:
        return None
    commit, requested_files = parsed_metadata
    repo = Path(source_repo).expanduser()
    if not repo.is_dir():
        raise ValueError("source repository path is not a directory")
    repo = repo.resolve()
    _run_git(repo, ["rev-parse", "--git-dir"], action="validate the source repository")
    raw_commit = _run_git(repo, ["rev-parse", "--verify", f"{commit}^{{commit}}"], action="resolve the patch commit")
    try:
        commit_oid = raw_commit.decode("ascii").strip().lower()
    except UnicodeDecodeError as exc:
        raise ValueError("git returned an invalid patch commit id") from exc
    if not _FULL_OBJECT_RE.fullmatch(commit_oid):
        raise ValueError("git returned an invalid patch commit id")

    raw_parents = _run_git(
        repo,
        ["rev-list", "--parents", "-n", "1", commit_oid],
        action="inspect the patch commit parents",
    )
    try:
        parent_tokens = raw_parents.decode("ascii").strip().lower().split()
    except UnicodeDecodeError as exc:
        raise ValueError("git returned an invalid patch parent id") from exc
    if not parent_tokens or parent_tokens[0] != commit_oid:
        raise ValueError("git returned an invalid patch parent list")
    parent_oids = parent_tokens[1:]
    if any(not _FULL_OBJECT_RE.fullmatch(parent_oid) for parent_oid in parent_oids):
        raise ValueError("git returned an invalid patch parent id")
    diff_parent_oid = parent_oids[0] if parent_oids else ""
    commit_range = [diff_parent_oid, commit_oid] if diff_parent_oid else ["--root", commit_oid]

    raw_changes = _run_git(
        repo,
        ["diff-tree", "--no-commit-id", "--name-status", "-r", "-z", "-M", *commit_range],
        action="inspect the patch commit",
    )
    changes = _parse_changed_files(raw_changes)
    files: list[PatchSourceFile] = []
    fingerprint_changes: list[dict[str, Any]] = []
    total_source_chars = 0
    for index, requested in enumerate(requested_files, start=1):
        change = changes.get(requested.path)
        if change is None:
            raise ValueError(f"metadata source file is not changed by the patch commit: {requested.path}")
        if change.change_type == "deleted":
            raise ValueError(f"patch source file is deleted by the patch commit: {requested.path}")
        mode, blob_oid = _ls_tree_blob(repo, commit_oid, requested.path)
        content = _read_blob(repo, blob_oid, requested.path)
        total_source_chars += len(content)
        if total_source_chars > MAX_SOURCE_TOTAL_CHARS:
            raise ValueError(
                f"patch source metadata exceeds the {MAX_SOURCE_TOTAL_CHARS}-character total limit"
            )
        lines = tuple(content.splitlines())
        for location in requested.locations:
            if (
                location.function_line_range is not None
                and location.function_line_range[1] > len(lines)
            ):
                raise ValueError(
                    f"patch source function range exceeds the post-patch source length: "
                    f"{requested.path}:{location.function}"
                )
            if any(line > len(lines) for line in location.changed_new_lines):
                raise ValueError(
                    f"patch source changed new line exceeds the post-patch source length: "
                    f"{requested.path}:{location.function}"
                )
        files.append(PatchSourceFile(
            source_file_id=f"source_{index:04d}",
            path=requested.path,
            locations=requested.locations,
            change_type=change.change_type,
            mode=mode,
            blob_oid=blob_oid,
            content=content,
            lines=lines,
        ))
        fingerprint_changes.append({
            "path": requested.path,
            "status": change.status,
            "change_type": change.change_type,
            "old_path": change.old_path,
        })

    fingerprint_payload = {
        "commit_oid": commit_oid,
        "parent_oids": parent_oids,
        "diff_parent_oid": diff_parent_oid,
        "diff_mapping": fingerprint_changes,
        "files": [
            {
                "path": source_file.path,
                "blob_oid": source_file.blob_oid,
                "mode": source_file.mode,
                "change_type": source_file.change_type,
                "locations": [location.agent_entry() for location in source_file.locations],
            }
            for source_file in files
        ],
    }
    encoded = json.dumps(
        fingerprint_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    context = PatchSourceContext(
        source_repo=repo,
        commit_oid=commit_oid,
        files=tuple(files),
        source_context_sha256=hashlib.sha256(encoded).hexdigest(),
    )
    manifest_size = len(json.dumps(context.agent_manifest(), ensure_ascii=False, separators=(",", ":")))
    if manifest_size > MAX_TOOL_RESULT_CHARS - 512:
        raise ValueError("patch source manifest exceeds the bounded tool-result limit")
    return context


def _tool_error(tool: str, message: str) -> dict[str, Any]:
    return {"ok": False, "tool": tool, "error": message}


def _active_context(tool: str) -> PatchSourceContext | dict[str, Any]:
    if _PATCH_SOURCE_CONTEXT is None:
        return _tool_error(tool, "patch source context is unavailable")
    return _PATCH_SOURCE_CONTEXT


def _begin_tool_call(tool: str) -> PatchSourceContext | dict[str, Any]:
    global _PATCH_SOURCE_TOOL_CALL_COUNT
    context = _active_context(tool)
    if isinstance(context, dict):
        return context
    if _PATCH_SOURCE_TOOL_CALL_COUNT >= SOURCE_TOOL_CALL_LIMIT:
        return _tool_error(tool, f"patch source tool call limit ({SOURCE_TOOL_CALL_LIMIT}) reached")
    _PATCH_SOURCE_TOOL_CALL_COUNT += 1
    return context


def _validated_file(
    tool: str,
    context: PatchSourceContext,
    source_file_id: Any,
) -> PatchSourceFile | dict[str, Any]:
    if not isinstance(source_file_id, str) or not source_file_id:
        return _tool_error(tool, "source_file_id must be a non-empty string")
    source_file = context.file_for_id(source_file_id)
    if source_file is None:
        return _tool_error(tool, "unknown source_file_id; call list_patch_sources first")
    return source_file


def _charge_source_chars(tool: str, result: dict[str, Any], source_chars: int) -> dict[str, Any]:
    global _PATCH_SOURCE_RETURNED_CHARS
    remaining = SOURCE_CONTEXT_CHAR_BUDGET - _PATCH_SOURCE_RETURNED_CHARS
    charged = dict(result)
    charged["source_chars"] = source_chars
    charged["result_chars"] = 0
    charged["budget_remaining_chars"] = remaining
    charged["_bounded_source_guidance"] = True
    result_chars = 0
    for _ in range(12):
        serialized = json.dumps(charged, ensure_ascii=False, separators=(",", ":"))
        result_chars = len(waf_safe_output(serialized, readable_json=True))
        budget_remaining = max(0, remaining - result_chars)
        if (
            charged["result_chars"] == result_chars
            and charged["budget_remaining_chars"] == budget_remaining
        ):
            break
        charged["result_chars"] = result_chars
        charged["budget_remaining_chars"] = budget_remaining
    else:
        return {
            "ok": False,
            "tool": tool,
            "error": "patch source result-size accounting did not converge",
            "budget_remaining_chars": max(0, remaining),
        }
    if result_chars > remaining:
        return {
            "ok": False,
            "tool": tool,
            "error": "patch source cumulative character budget would be exceeded",
            "budget_remaining_chars": max(0, remaining),
        }
    _PATCH_SOURCE_RETURNED_CHARS += result_chars
    charged["result_chars"] = result_chars
    charged["budget_remaining_chars"] = SOURCE_CONTEXT_CHAR_BUDGET - _PATCH_SOURCE_RETURNED_CHARS
    return charged


def _bounded_numbered_lines(
    lines: tuple[str, ...],
    start_line: int,
    end_line: int,
    *,
    max_lines: int,
    max_chars: int,
) -> dict[str, Any]:
    limited_end = min(end_line, start_line + max_lines - 1)
    pieces: list[str] = []
    retained_chars = 0
    last_line = start_line - 1
    omitted_chars_in_last_line = 0
    char_truncated = False
    for line_number in range(start_line, limited_end + 1):
        prefix = "" if not pieces else "\n"
        rendered = f"{line_number}: {lines[line_number - 1]}"
        remaining = max_chars - retained_chars
        if remaining <= len(prefix):
            char_truncated = True
            break
        candidate = prefix + rendered
        if len(candidate) <= remaining:
            pieces.append(candidate)
            retained_chars += len(candidate)
            last_line = line_number
            continue
        available = remaining - len(prefix)
        if available > 0:
            if available == 1:
                shortened = "…"
            else:
                shortened = rendered[:available - 1] + "…"
            pieces.append(prefix + shortened)
            retained_chars += len(prefix) + len(shortened)
            last_line = line_number
            omitted_chars_in_last_line = max(0, len(rendered) - max(0, available - 1))
        char_truncated = True
        break
    line_truncated = limited_end < end_line
    return {
        "content": "".join(pieces),
        "end_line": last_line,
        "returned_line_count": max(0, last_line - start_line + 1),
        "truncated": bool(char_truncated or line_truncated),
        "char_truncated": char_truncated,
        "omitted_chars_in_last_line": omitted_chars_in_last_line,
        "next_start_line": last_line + 1 if last_line < end_line else None,
    }


def list_patch_sources() -> dict[str, Any]:
    """List source file ids, patch functions, and changed post-patch ranges."""
    context = _begin_tool_call("list_patch_sources")
    if isinstance(context, dict):
        return context
    manifest = context.agent_manifest()
    result = {
        "ok": True,
        "tool": "list_patch_sources",
        "source_file_count": len(context.files),
        **manifest,
    }
    return _charge_source_chars("list_patch_sources", result, 0)


def read_patch_source(source_file_id: str, start_line: int, end_line: int) -> dict[str, Any]:
    """Read a bounded, numbered line range from one allowlisted source blob."""
    tool = "read_patch_source"
    context = _begin_tool_call(tool)
    if isinstance(context, dict):
        return context
    source_file = _validated_file(tool, context, source_file_id)
    if isinstance(source_file, dict):
        return source_file
    if (
        not isinstance(start_line, int)
        or isinstance(start_line, bool)
        or not isinstance(end_line, int)
        or isinstance(end_line, bool)
        or start_line < 1
        or end_line < start_line
    ):
        return _tool_error(tool, "start_line and end_line must define a positive ordered range")
    total_lines = len(source_file.lines)
    if start_line > total_lines:
        return _tool_error(tool, "start_line exceeds the source file length")
    requested_end = min(end_line, total_lines)
    bounded = _bounded_numbered_lines(
        source_file.lines,
        start_line,
        requested_end,
        max_lines=MAX_READ_LINES,
        max_chars=MAX_READ_CHARS,
    )
    result = {
        "ok": True,
        "tool": tool,
        "source_file_id": source_file.source_file_id,
        "path": source_file.path,
        "start_line": start_line,
        "total_lines": total_lines,
        **bounded,
    }
    return _charge_source_chars(tool, result, len(bounded["content"]))


def search_patch_source(
    query: str,
    source_file_id: str = "",
    context_lines: int = 0,
    max_results: int = 20,
) -> dict[str, Any]:
    """Search literal text within the allowlisted patch-after source files."""
    tool = "search_patch_source"
    context = _begin_tool_call(tool)
    if isinstance(context, dict):
        return context
    if (
        not isinstance(query, str)
        or not query
        or len(query) > MAX_QUERY_CHARS
        or "\x00" in query
        or "\n" in query
        or "\r" in query
    ):
        return _tool_error(tool, f"query must be a non-empty single-line string up to {MAX_QUERY_CHARS} characters")
    if (
        not isinstance(context_lines, int)
        or isinstance(context_lines, bool)
        or context_lines < 0
        or context_lines > MAX_SEARCH_CONTEXT_LINES
    ):
        return _tool_error(tool, f"context_lines must be between 0 and {MAX_SEARCH_CONTEXT_LINES}")
    if not isinstance(max_results, int) or isinstance(max_results, bool) or max_results < 1:
        return _tool_error(tool, "max_results must be a positive integer")
    result_limit = min(max_results, MAX_SEARCH_RESULTS)
    if source_file_id:
        source_file = _validated_file(tool, context, source_file_id)
        if isinstance(source_file, dict):
            return source_file
        source_files = (source_file,)
    else:
        source_files = context.files

    matches: list[dict[str, Any]] = []
    total_matches = 0
    retained_chars = 0
    output_truncated = False
    for source_file in source_files:
        for index, line in enumerate(source_file.lines):
            if query not in line:
                continue
            total_matches += 1
            if len(matches) >= result_limit:
                output_truncated = True
                continue
            line_number = index + 1
            excerpt_start = max(1, line_number - context_lines)
            excerpt_end = min(len(source_file.lines), line_number + context_lines)
            available = MAX_SEARCH_CHARS - retained_chars
            if available <= 0:
                output_truncated = True
                continue
            bounded = _bounded_numbered_lines(
                source_file.lines,
                excerpt_start,
                excerpt_end,
                max_lines=2 * context_lines + 1,
                max_chars=available,
            )
            if not bounded["content"]:
                output_truncated = True
                continue
            candidate = {
                "source_file_id": source_file.source_file_id,
                "path": source_file.path,
                "line_number": line_number,
                "context_start_line": excerpt_start,
                "context_end_line": bounded["end_line"],
                "content": bounded["content"],
                "content_truncated": bounded["truncated"],
            }
            candidate_size = len(json.dumps(
                {"matches": [*matches, candidate]},
                ensure_ascii=False,
                separators=(",", ":"),
            ))
            if candidate_size > MAX_TOOL_RESULT_CHARS - 768:
                output_truncated = True
                continue
            retained_chars += len(bounded["content"])
            matches.append(candidate)
            if bounded["truncated"]:
                output_truncated = True
    result = {
        "ok": True,
        "tool": tool,
        "query": query,
        "matches": matches,
        "returned_results": len(matches),
        "total_matches": total_matches,
        "truncated": bool(output_truncated or total_matches > len(matches)),
    }
    return _charge_source_chars(
        tool,
        result,
        sum(len(match["content"]) for match in matches),
    )


def _ctags_function_range(source_file: PatchSourceFile, function_name: str) -> tuple[int, int] | None:
    executable = shutil.which("ctags")
    if executable is None:
        return None
    try:
        version = _run_bounded_process(
            [executable, "--version"],
            timeout=CTAGS_TIMEOUT_SEC,
            max_stdout_bytes=64 * 1024,
        )
    except (OSError, subprocess.TimeoutExpired, _ProcessOutputLimitError):
        return None
    if version.returncode != 0 or b"Universal Ctags" not in version.stdout:
        return None

    suffix = PurePosixPath(source_file.path).suffix or ".c"
    try:
        with tempfile.TemporaryDirectory(prefix="claudeagent-patch-source-") as temporary_dir:
            temporary_path = Path(temporary_dir) / f"source{suffix}"
            temporary_path.write_text(source_file.content, encoding="utf-8")
            proc = _run_bounded_process(
                [
                    executable,
                    "--options=NONE",
                    "--output-format=json",
                    "--fields=+ne",
                    "--extras=-F",
                    "--kinds-all=f",
                    "--sort=no",
                    "-o",
                    "-",
                    str(temporary_path),
                ],
                timeout=CTAGS_TIMEOUT_SEC,
                max_stdout_bytes=MAX_CTAGS_STDOUT_BYTES,
            )
    except (OSError, subprocess.TimeoutExpired, _ProcessOutputLimitError):
        return None
    if proc.returncode != 0:
        return None
    candidates: list[tuple[int, int]] = []
    for raw_line in proc.stdout.splitlines():
        try:
            tag = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if tag.get("_type") != "tag" or tag.get("name") != function_name:
            continue
        if str(tag.get("kind", "")).lower() not in {"function", "method", "subroutine", "procedure"}:
            continue
        start = tag.get("line")
        end = tag.get("end")
        if (
            isinstance(start, int)
            and not isinstance(start, bool)
            and isinstance(end, int)
            and not isinstance(end, bool)
            and 1 <= start <= end <= len(source_file.lines)
        ):
            candidates.append((start, end))
    if not candidates:
        return None
    return min(candidates, key=lambda item: (item[1] - item[0], item[0]))


def _mask_c_like_source(content: str) -> str:
    characters = list(content)
    state = "code"
    index = 0
    while index < len(characters):
        char = characters[index]
        next_char = characters[index + 1] if index + 1 < len(characters) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                characters[index] = characters[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                characters[index] = characters[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char == '"':
                characters[index] = " "
                state = "string"
            elif char == "'":
                characters[index] = " "
                state = "character"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                characters[index] = " "
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                characters[index] = characters[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                characters[index] = " "
        elif state in {"string", "character"}:
            delimiter = '"' if state == "string" else "'"
            if char == "\\":
                characters[index] = " "
                if index + 1 < len(characters) and characters[index + 1] != "\n":
                    characters[index + 1] = " "
                index += 2
                continue
            if char == delimiter:
                characters[index] = " "
                state = "code"
            elif char != "\n":
                characters[index] = " "
        index += 1
    return "".join(characters)


def _matching_delimiter(content: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(content)):
        if content[index] == opening:
            depth += 1
        elif content[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _fallback_function_range(source_file: PatchSourceFile, function_name: str) -> tuple[int, int] | None:
    masked = _mask_c_like_source(source_file.content)
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(function_name)}(?![A-Za-z0-9_])\s*\(")
    for match in pattern.finditer(masked):
        opening_parenthesis = masked.find("(", match.start())
        closing_parenthesis = _matching_delimiter(masked, opening_parenthesis, "(", ")")
        if closing_parenthesis is None:
            continue
        scan_end = min(len(masked), closing_parenthesis + 4096)
        opening_brace = None
        invalid_candidate = False
        parenthesis_depth = 0
        bracket_depth = 0
        for index in range(closing_parenthesis + 1, scan_end):
            char = masked[index]
            if char == "(":
                parenthesis_depth += 1
                continue
            if char == ")":
                if parenthesis_depth <= 0:
                    invalid_candidate = True
                    break
                parenthesis_depth -= 1
                continue
            if char == "[":
                bracket_depth += 1
                continue
            if char == "]":
                if bracket_depth <= 0:
                    invalid_candidate = True
                    break
                bracket_depth -= 1
                continue
            if char == ";" and parenthesis_depth == 0 and bracket_depth == 0:
                invalid_candidate = True
                break
            if char == "{" and parenthesis_depth == 0 and bracket_depth == 0:
                opening_brace = index
                break
            if char in "=," and parenthesis_depth == 0 and bracket_depth == 0:
                invalid_candidate = True
                break
        if invalid_candidate or opening_brace is None:
            continue
        closing_brace = _matching_delimiter(masked, opening_brace, "{", "}")
        if closing_brace is None:
            continue
        start_line = masked.count("\n", 0, match.start()) + 1
        end_line = masked.count("\n", 0, closing_brace) + 1
        return start_line, end_line
    return None


def read_patch_function(source_file_id: str, function_name: str, context_lines: int = 12) -> dict[str, Any]:
    """Read one metadata-declared function from an allowlisted source blob."""
    tool = "read_patch_function"
    context = _begin_tool_call(tool)
    if isinstance(context, dict):
        return context
    source_file = _validated_file(tool, context, source_file_id)
    if isinstance(source_file, dict):
        return source_file
    if not isinstance(function_name, str) or function_name not in source_file.functions:
        return _tool_error(tool, "function_name is not declared for this patch source file")
    if (
        not isinstance(context_lines, int)
        or isinstance(context_lines, bool)
        or context_lines < 0
        or context_lines > MAX_FUNCTION_CONTEXT_LINES
    ):
        return _tool_error(tool, f"context_lines must be between 0 and {MAX_FUNCTION_CONTEXT_LINES}")

    location = source_file.location_for_function(function_name)
    function_range = location.function_line_range if location is not None else None
    locator = "metadata_location"
    if function_range is None:
        function_range = _ctags_function_range(source_file, function_name)
        locator = "universal_ctags"
    if function_range is None:
        function_range = _fallback_function_range(source_file, function_name)
        locator = "bounded_fallback"
    if function_range is None:
        return _tool_error(tool, "the declared function could not be located in the patch source blob")
    definition_start, definition_end = function_range
    output_start = max(1, definition_start - context_lines)
    output_end = min(len(source_file.lines), definition_end + context_lines)
    bounded = _bounded_numbered_lines(
        source_file.lines,
        output_start,
        output_end,
        max_lines=MAX_FUNCTION_LINES,
        max_chars=MAX_FUNCTION_CHARS,
    )
    result = {
        "ok": True,
        "tool": tool,
        "source_file_id": source_file.source_file_id,
        "path": source_file.path,
        "function_name": function_name,
        "locator": locator,
        "definition_start_line": definition_start,
        "definition_end_line": definition_end,
        "start_line": output_start,
        "total_lines": len(source_file.lines),
        **bounded,
    }
    return _charge_source_chars(tool, result, len(bounded["content"]))
