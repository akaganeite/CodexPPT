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
    scratch = os.path.join(tmp, "scratch")
    os.makedirs(scratch, exist_ok=True)
    dis = os.path.join(scratch, "dis.txt")
    with open(dis, "w") as fh:
        fh.write("0: cmp eax,0x9\n")

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
        (["xxd", "-s", "0xb8e20", "-l", "64", binary], "xxd byte window on target"),
        (["od", "-A", "x", "-t", "x1z", "-j", "0xb8e20", "-N", "64", binary], "od byte window on target"),
        (["hexdump", "-C", "-s", "0x1000", "-n", "32", binary], "hexdump on target"),
        (["sh", "-lc", f"strings -a -tx {binary} | head -5"], "pipeline strings->head"),
        (["sh", "-lc", "echo '0x80 + 0x200' | bc"], "bc arithmetic"),
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
        (["dd", f"if={binary}", "bs=1", "skip=4096", "count=64"], "dd still denied (if=/of= bypass risk)"),
        (["sh", "-lc", f"dd if={binary} bs=1 skip=0 count=16"], "dd in pipeline denied"),
        (["xxd", "-s", "0", "-l", "16", sibling_debug], "xxd on sibling debug"),
        (["od", "-t", "x1", source], "od on source file"),
        (["sh", "-lc", f"xxd {sibling_debug}"], "xxd sibling debug in pipeline"),
    ]

    # Cases evaluated WITH a scratch dir (decide_command(argv, binary, scratch)).
    allow_scratch = [
        (["sh", "-lc", f"objdump -d -Mintel {binary} > {dis}"], "dump objdump into scratch"),
        (["sh", "-lc", f"objdump -d -Mintel {binary} > {scratch}/d.txt"], "dump into scratch (new file)"),
        (["sh", "-lc", f"grep -n -C 8 'cmp' {dis} | head -40"], "grep a scratch file"),
        (["cat", dis], "cat a scratch file (direct)"),
        (["sh", "-lc", f"strings -a -tx {binary} > {scratch}/s.txt"], "dump strings into scratch"),
        (["sh", "-lc", f"objdump -d {binary} 2>&1 | grep call > {scratch}/c.txt"], "fd dup + redirect to scratch"),
        (["sh", "-lc", f"objdump -d -Mintel {binary} 2>/dev/null > {scratch}/d.txt"], "stderr to /dev/null + dump"),
        (["sh", "-lc", f"grep -n cmp {dis} 2>/dev/null | head -20"], "inline 2>/dev/null"),
        (["sh", "-lc", f"readelf -S {binary} > /dev/null"], "redirect to /dev/null"),
    ]
    forbid_scratch = [
        (["sh", "-lc", f"objdump -d {binary} > /tmp/evil.txt"], "redirect outside scratch"),
        (["sh", "-lc", f"objdump -d {binary} > {tmp}/escape.txt"], "redirect to tmp (outside scratch)"),
        (["sh", "-lc", f"cat /etc/passwd > {scratch}/x"], "external content into scratch (cat denied)"),
        (["sh", "-lc", f"cat {source} > {scratch}/x"], "source into scratch (cat denied)"),
        (["sh", "-lc", f"grep x {sibling_debug} > {scratch}/x"], "read sibling debug into scratch"),
        (["sh", "-lc", f"objdump -d {binary} >> /tmp/evil.txt"], "append outside scratch"),
        (["sh", "-lc", f"objdump -d {binary} 2>/tmp/err.txt"], "stderr inline to /tmp (outside scratch)"),
        (["sh", "-lc", f"grep x {binary} < {source}"], "input redirection from source"),
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
    for argv, label in allow_scratch:
        decision, reason = decide_command(argv, binary, scratch)
        if decision is not Decision.ALLOW:
            failures.append(f"EXPECTED ALLOW (scratch) but got FORBID: {label}: {reason}")
    for argv, label in forbid_scratch:
        decision, reason = decide_command(argv, binary, scratch)
        if decision is not Decision.FORBID:
            failures.append(f"EXPECTED FORBID (scratch) but got ALLOW: {label}")

    if failures:
        print("POLICY TESTS FAILED:")
        for line in failures:
            print("  -", line)
        return 1
    print(f"POLICY TESTS PASSED ({len(allow)+len(allow_scratch)} allow, {len(forbid)+len(forbid_scratch)} forbid)")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
