"""Read-only command policy: allowlist + debug/source denylist + path confinement.

This is the enforcement layer for the harness's two non-negotiable input rules:

1. Only read-only binutils/filter commands may run (default-deny allowlist).
2. The model may observe ONLY the one resolved target binary. Any argv token that
   resolves to an existing file must be that binary; sibling debug/unstripped
   artifacts, source files, and source repos are rejected even by path shape.

Decisions are three-state in spirit (codex execpolicy) but collapse to ALLOW /
FORBID here because the harness is non-interactive (no human approval step).
"""

from __future__ import annotations

import os
import re
import shlex
from enum import Enum
from pathlib import Path
from typing import Optional


class Decision(Enum):
    ALLOW = "allow"
    FORBID = "forbid"


# Programs that read/inspect the binary.
ALLOWED_COMMANDS = {
    "file",
    "readelf",
    "objdump",
    "nm",
    "strings",
    "c++filt",
    "size",
    "sha1sum",
    "sha256sum",
}
# Text filters usable inside `sh -lc` pipelines.
SAFE_FILTERS = {
    "grep",
    "rg",
    "egrep",
    "fgrep",
    "head",
    "tail",
    "sort",
    "uniq",
    "wc",
    "awk",
    "sed",
    "cut",
    "tr",
    "cat",
    "printf",
    "echo",
    "true",
    "false",
    "test",
    "[",
}
# `sh` is allowed only as `sh -lc <pipeline>`.
COMMAND_POSITION_OK = ALLOWED_COMMANDS | SAFE_FILTERS

# Denied shell patterns (defense-in-depth, applied to the whole script string).
DENIED_SHELL_PATTERNS = [
    re.compile(r"(^|[\s;&|(])(?:rm|mv|cp|chmod|chown|dd|truncate|touch|mkdir|rmdir|ln|install|tee|xargs|env|python|python3|perl|ruby|node|gdb|lldb|strace|ltrace)\b"),
    re.compile(r"(^|[\s;&|(])addr2line\b"),
    re.compile(r"readelf\b[^;&|]*?(?:--debug-dump(?:=|\b)|\s-w[a-zA-Z=]*)"),
    re.compile(r"objdump\b[^;&|]*?(?:\s-S\b|--source\b|\s-g\b|--debugging\b|\s-W\b|--dwarf\b|--line-numbers\b|\s-l\b)"),
    re.compile(r"\$\(|`|<\("),                    # command/process substitution
    re.compile(r"(?<![12])>\s*[^&]"),             # output redirection to a file
    re.compile(r"(?<![12])>>"),
]

# Denied path shapes: source files, debug/unstripped siblings, source repos.
# Applied to the full command/script text AND to each individual token.
DENIED_PATH_PATTERNS = [
    re.compile(r"\.debug\b"),
    re.compile(r"(^|[\s/])[\w.-]*_debug\b"),
    re.compile(r"\.dwo\b"),
    re.compile(r"/usr/lib/debug/"),
    re.compile(r"\.(c|h|cc|cpp|cxx|hpp|hxx|c\+\+|inc)(\b|$)"),
    re.compile(r"/extrepo/|/CVE-Dataset|(^|/)src/"),
]


def _denied_path_reason(text: str) -> Optional[str]:
    for pattern in DENIED_PATH_PATTERNS:
        if pattern.search(text):
            return f"command references a denied debug/source path shape: {pattern.pattern}"
    return None


def _resolved(path: str) -> str:
    try:
        return os.path.realpath(os.path.expanduser(path))
    except Exception:
        return path


def _token_is_confined(token: str, binary_real: str) -> tuple[bool, str]:
    """A token that resolves to an existing file must BE the target binary."""
    denied = _denied_path_reason(token)
    if denied:
        return False, denied
    # Only tokens that look like a path and actually exist as a file are confined.
    candidate = os.path.expanduser(token)
    try:
        is_file = os.path.isfile(candidate)
    except Exception:
        is_file = False
    if is_file and _resolved(candidate) != binary_real:
        return False, (
            f"command reads a file other than the target binary: {token!r}; "
            "only the one resolved target binary may be inspected"
        )
    return True, ""


def validate_no_debug_source_args(command: str, argv: list[str]) -> tuple[bool, str]:
    if command == "readelf":
        for item in argv[1:]:
            if item.startswith("--debug-dump") or re.fullmatch(r"-w[a-zA-Z=]*", item):
                return False, "readelf debug/DWARF dumps are not allowed in the target-binary-only path"
    if command == "objdump":
        denied = {"-S", "--source", "-g", "--debugging", "-W", "--dwarf", "-l", "--line-numbers"}
        for item in argv[1:]:
            if item in denied or item.startswith("--dwarf"):
                return False, "objdump source/debug/line-number options are not allowed in the target-binary-only path"
    return True, ""


def validate_shell_script(script: str, binary_real: str) -> tuple[bool, str]:
    for pattern in DENIED_SHELL_PATTERNS:
        if pattern.search(script):
            return False, f"shell command contains denied pattern: {pattern.pattern}"
    denied = _denied_path_reason(script)
    if denied:
        return False, denied
    try:
        tokens = shlex.split(script)
    except ValueError as exc:
        return False, f"cannot parse shell command: {exc}"
    command_expected = True
    for token in tokens:
        if token in {"|", "&&", "||", ";", "(", ")"}:
            command_expected = token != ")"
            continue
        if command_expected and "=" in token and not token.startswith(("/", ".", "-")):
            # leading VAR=value assignment, stay in command position
            continue
        if command_expected:
            base = Path(token).name
            if base not in COMMAND_POSITION_OK:
                return False, f"unsupported shell command: {token}"
            command_expected = False
        ok, reason = _token_is_confined(token, binary_real)
        if not ok:
            return False, reason
    return True, ""


def decide_command(argv: list[str], binary_path: str) -> tuple[Decision, str]:
    """Decide whether a tool's argv may run against the one target binary."""
    if not argv:
        return Decision.FORBID, "argv is empty"
    for item in argv:
        if "\x00" in item or "\n" in item:
            return Decision.FORBID, "argv item contains NUL/newline"
    binary_real = _resolved(binary_path) if binary_path else ""
    command = Path(argv[0]).name

    if command == "sh":
        if len(argv) != 3 or argv[1] != "-lc":
            return Decision.FORBID, "sh is only allowed as: sh -lc <read-only binutils/filter pipeline>"
        ok, reason = validate_shell_script(argv[2], binary_real)
        return (Decision.ALLOW, "") if ok else (Decision.FORBID, reason)

    if command not in COMMAND_POSITION_OK:
        return Decision.FORBID, f"command is not allowed: {argv[0]}"

    ok, reason = validate_no_debug_source_args(command, argv)
    if not ok:
        return Decision.FORBID, reason
    for item in argv:
        ok, reason = _token_is_confined(item, binary_real)
        if not ok:
            return Decision.FORBID, reason
    return Decision.ALLOW, ""
