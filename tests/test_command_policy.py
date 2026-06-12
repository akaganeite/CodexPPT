"""Adversarial tests for the command policy. Run before any model is in the loop:

    python3 -m claudeagent.tests.test_command_policy
"""

from __future__ import annotations

import os
import sys
import tempfile

from claudeagent.command_policy import Decision, decide_command


def _run() -> int:
    tmp = tempfile.mkdtemp(prefix="claudeagent-policy-")
    binary = os.path.join(tmp, "curl_stripped")
    sibling_debug = os.path.join(tmp, "curl_debug")
    source = os.path.join(tmp, "sasl.c")
    for path in (binary, sibling_debug, source):
        with open(path, "wb") as fh:
            fh.write(b"\x7fELF stub")

    allow = [
        (["file", binary], "file on target"),
        (["readelf", "-h", binary], "readelf header"),
        (["readelf", "-d", binary], "readelf dynamic"),
        (["objdump", "-d", "-Mintel", binary], "objdump disassembly"),
        (["strings", "-a", "-tx", binary], "strings offsets"),
        (["nm", "-D", binary], "dynamic symbols"),
        (["sh", "-lc", f"strings -a -tx {binary} | rg -n -C8 '0x6f158' | head -40"], "pipeline strings->rg"),
        (["sh", "-lc", f"objdump -d -Mintel {binary} | grep -n 'call' | head -20"], "pipeline objdump->grep"),
        (["sh", "-lc", "readelf -h " + binary], "pipeline single readelf"),
    ]
    forbid = [
        (["objdump", "-S", binary], "objdump source interleave"),
        (["objdump", "-d", "--dwarf=info", binary], "objdump dwarf"),
        (["readelf", "--debug-dump=info", binary], "readelf debug-dump"),
        (["readelf", "-wi", binary], "readelf -w dwarf"),
        (["addr2line", "-e", binary, "0x1000"], "addr2line"),
        (["objdump", "-d", sibling_debug], "sibling debug binary"),
        (["cat", source], "source file read"),
        (["cat", "/etc/passwd"], "arbitrary file read"),
        (["python3", "-c", "print(1)"], "interpreter"),
        (["rm", "-rf", binary], "destructive"),
        (["sh", "-lc", f"cat {source}"], "pipeline source read"),
        (["sh", "-lc", f"objdump -d {binary} > /tmp/out.txt"], "pipeline redirection"),
        (["sh", "-lc", f"objdump -d {binary} | cat /usr/lib/debug/foo"], "pipeline debug path"),
        (["sh", "-lc", "cat *.c"], "pipeline glob source"),
        (["sh", "-lc", f"echo $(rm {binary})"], "command substitution"),
        (["sh", "-lc", f"objdump -d {sibling_debug}"], "pipeline sibling debug"),
        (["sh", "-i"], "sh wrong form"),
        (["ls", tmp], "ls not allowed"),
    ]

    failures = []
    for argv, label in allow:
        decision, reason = decide_command(argv, binary)
        if decision is not Decision.ALLOW:
            failures.append(f"EXPECTED ALLOW but got FORBID: {label}: {reason}")
    for argv, label in forbid:
        decision, reason = decide_command(argv, binary)
        if decision is not Decision.FORBID:
            failures.append(f"EXPECTED FORBID but got ALLOW: {label}")

    if failures:
        print("POLICY TESTS FAILED:")
        for line in failures:
            print("  -", line)
        return 1
    print(f"POLICY TESTS PASSED ({len(allow)} allow, {len(forbid)} forbid)")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
