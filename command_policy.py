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
#
# xxd / od / hexdump dump raw bytes at a given offset (e.g. `xxd -s 0xb8e20 -l 48
# <binary>`); they take a normal file argument so path confinement applies, and
# they write only to stdout (writing a file needs redirection, which is denied).
# bc is pure arithmetic for offset/size math. `dd` is deliberately NOT here: its
# if=/of= are key=value tokens that bypass per-token path confinement and of= can
# write files, so it stays on the denylist; xxd/od cover the same read use safely.
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
    "xxd",
    "od",
    "hexdump",
    "bc",
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
]

# Redirection policy (enforced token-by-token in validate_shell_script): output
# may be redirected only to /dev/null or into the scratch dir, so the model can
# dump a big disassembly once and grep it many times, and can silence stderr with
# `2>/dev/null`. fd-to-fd dups like `2>&1` / `>&2` are fine. Input redirection
# (`<`) and any other redirect target are rejected.
_FD_TO_FD = re.compile(r"^[0-9]*>&[0-9-]+$")            # 2>&1, >&2, 1>&-
_INLINE_REDIR = re.compile(r"^&?[0-9]*>>?(.+)$")        # 2>file, >file, &>file, 1>>file
_REDIR_OPS = {">", ">>", "&>", "&>>"}                   # target is the next token

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


def _in_scratch(path: str, scratch_real: str) -> bool:
    """True if path resolves inside the per-case scratch dir."""
    if not scratch_real:
        return False
    rp = _resolved(path)
    return rp == scratch_real or rp.startswith(scratch_real + os.sep)


def _redir_target_ok(target: str, scratch_real: str) -> bool:
    """A redirection target is allowed only if it is /dev/null or in the scratch dir."""
    return target == "/dev/null" or _in_scratch(target, scratch_real)


def _token_is_confined(token: str, binary_real: str, scratch_real: str = "") -> tuple[bool, str]:
    """A token that resolves to an existing file must BE the target binary.

    Files inside the scratch dir are allowed: they can only hold output derived
    from the target binary (commands that read other files are rejected first),
    so reading/writing them does not widen the model's input beyond the binary.
    """
    if _in_scratch(token, scratch_real):
        return True, ""
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


def validate_shell_script(script: str, binary_real: str, scratch_real: str = "") -> tuple[bool, str]:
    for pattern in DENIED_SHELL_PATTERNS:
        if pattern.search(script):
            return False, f"shell command contains denied pattern: {pattern.pattern}"
    try:
        tokens = shlex.split(script)
    except ValueError as exc:
        return False, f"cannot parse shell command: {exc}"
    command_expected = True
    expect_redirect_target = False
    redir_err = "redirection target must be /dev/null or a path inside the scratch dir"
    for token in tokens:
        if expect_redirect_target:
            expect_redirect_target = False
            if not _redir_target_ok(token, scratch_real):
                return False, redir_err
            continue
        if token in {"|", "&&", "||", ";", "(", ")"}:
            command_expected = token != ")"
            continue
        if token in _REDIR_OPS:              # standalone `>` / `>>` / `&>` ; target is next token
            expect_redirect_target = True
            command_expected = False
            continue
        if _FD_TO_FD.match(token):           # 2>&1, >&2, 1>&- : fd dup, not a file
            command_expected = False
            continue
        inline = _INLINE_REDIR.match(token)  # 2>/dev/null, >scratch/x, 1>>scratch/x
        if inline and not inline.group(1).startswith("&"):
            if not _redir_target_ok(inline.group(1), scratch_real):
                return False, redir_err
            command_expected = False
            continue
        if ">" in token or "<" in token:
            return False, (
                "unsupported redirection; redirect only to /dev/null or a scratch_dir path "
                "(fd dups like 2>&1 are allowed; input redirection `<` is not)"
            )
        if command_expected and "=" in token and not token.startswith(("/", ".", "-")):
            # leading VAR=value assignment, stay in command position
            continue
        if command_expected:
            base = Path(token).name
            if base not in COMMAND_POSITION_OK:
                return False, f"unsupported shell command: {token}"
            command_expected = False
        ok, reason = _token_is_confined(token, binary_real, scratch_real)
        if not ok:
            return False, reason
    if expect_redirect_target:
        return False, "dangling redirection with no target"
    # Path-shape denylist over the whole script, but tolerate scratch-dir paths.
    sanitized = re.sub(r"\S+", lambda m: "" if _in_scratch(m.group(0), scratch_real) else m.group(0), script)
    denied = _denied_path_reason(sanitized)
    if denied:
        return False, denied
    return True, ""


def decide_command(argv: list[str], binary_path: str, scratch_dir: str = "") -> tuple[Decision, str]:
    """Decide whether a tool's argv may run against the one target binary."""
    if not argv:
        return Decision.FORBID, "argv is empty"
    for item in argv:
        if "\x00" in item or "\n" in item:
            return Decision.FORBID, "argv item contains NUL/newline"
    binary_real = _resolved(binary_path) if binary_path else ""
    scratch_real = _resolved(scratch_dir) if scratch_dir else ""
    command = Path(argv[0]).name

    if command == "sh":
        if len(argv) != 3 or argv[1] != "-lc":
            return Decision.FORBID, "sh is only allowed as: sh -lc <read-only binutils/filter pipeline>"
        ok, reason = validate_shell_script(argv[2], binary_real, scratch_real)
        return (Decision.ALLOW, "") if ok else (Decision.FORBID, reason)

    if command not in COMMAND_POSITION_OK:
        return Decision.FORBID, f"command is not allowed: {argv[0]}"

    ok, reason = validate_no_debug_source_args(command, argv)
    if not ok:
        return Decision.FORBID, reason
    for item in argv:
        ok, reason = _token_is_confined(item, binary_real, scratch_real)
        if not ok:
            return Decision.FORBID, reason
    return Decision.ALLOW, ""
