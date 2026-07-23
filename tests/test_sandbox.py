"""Tests for the bubblewrap sandbox and the run_python tool.

    python3 -m claudeagent.tests.test_sandbox

These verify the confinement contract (the OS-enforced counterpart to the old
argv-level command policy): the script cannot reach /etc, /home, or the network,
but CAN read /workspace/binary and call binutils, and CAN write /scratch. Also
exercises run_python end-to-end: it mints an observation + one pending
command_output evidence id that must later be returned to and summarized by the
main Agent before finalization can cite it.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from claudeagent.host import run_host_cmd
from claudeagent.run_python_tool import run_python
from claudeagent.runtime import AGENT_CONTEXT, initialize_agent_context


# A real stripped ELF is needed so the sandbox has something read-only to mount.
_CANDIDATE_BINARIES = [
    os.path.expanduser("~/extdisk/dataset4ppt/curl/binaries/target/curl_stripped/curl-7.29.0-libcurl-gcc-O0"),
    "/bin/ls",
    "/usr/bin/ls",
]


def _find_binary() -> str | None:
    for path in _CANDIDATE_BINARIES:
        if os.path.isfile(path):
            return path
    return None


def _run_sandbox_probe(binary: str, script: str) -> str:
    """Write `script` under a scratch dir, run it confined, return stdout."""
    with tempfile.TemporaryDirectory(prefix="claudeagent-test-sandbox-") as tmp:
        sp = Path(tmp) / "probe.py"
        sp.write_text(script)
        from claudeagent.sandbox import run_in_sandbox
        res = run_in_sandbox(script_path=str(sp), scratch_dir=tmp, binary_path=binary, timeout=30)
        return (res.get("stdout") or "") + "\n---STDERR---\n" + (res.get("stderr") or "")


def _run() -> int:
    binary = _find_binary()
    failures: list[str] = []

    def check(label: str, cond: bool) -> None:
        if not cond:
            failures.append(label)

    # 1. preflight: bwrap usable.
    from claudeagent.sandbox import preflight_sandbox
    pf = preflight_sandbox()
    check("preflight ok", bool(pf.get("ok")))
    if not pf.get("ok"):
        print("SANDBOX_PREFLIGHT_FAILED:", pf)
        # If bwrap is unavailable in this environment we cannot run the rest; report and stop.
        print("FAIL: sandbox unavailable")
        return 1

    if binary is None:
        print("SKIP: no test binary available")
        return 0

    # 2. confinement: /etc/passwd must be unreachable.
    out = _run_sandbox_probe(binary, "try:\n    open('/etc/passwd')\n    print('LEAK_ETC')\nexcept FileNotFoundError:\n    print('CONFINED_ETC')\n")
    check("/etc confined", "CONFINED_ETC" in out and "LEAK_ETC" not in out)

    # 3. confinement: /home must be invisible.
    out = _run_sandbox_probe(binary, "import os\ntry:\n    print('HOME_LIST', os.listdir('/home'))\nexcept Exception as e:\n    print('CONFINED_HOME', repr(e))\n")
    check("/home confined", "CONFINED_HOME" in out and "HOME_LIST" not in out)

    # 4. the target binary is readable at the fixed path.
    out = _run_sandbox_probe(binary, "print('MAGIC', open('/workspace/binary','rb').read(4))\n")
    check("binary readable", b"\\x7fELF" in out.encode() or "7fELF" in out or "ELF" in out)

    # 5. binutils callable inside the sandbox.
    out = _run_sandbox_probe(binary, "import subprocess\nr=subprocess.run(['readelf','-h','/workspace/binary'],capture_output=True,text=True)\nprint('READELF_RC', r.returncode)\n")
    check("readelf works", "READELF_RC 0" in out)

    # 6. network isolated.
    out = _run_sandbox_probe(binary, "import socket\ntry:\n    socket.create_connection(('1.1.1.1',53),2)\n    print('NET_LEAK')\nexcept Exception as e:\n    print('NET_ISOLATED', type(e).__name__)\n")
    check("network isolated", "NET_ISOLATED" in out and "NET_LEAK" not in out)

    # 7. scratch writable.
    out = _run_sandbox_probe(binary, "open('/scratch/out.txt','w').write('ok')\nprint('SCRATCH_OK')\n")
    check("scratch writable", "SCRATCH_OK" in out)

    # 8. run_python end-to-end: mints obs + one command_output evidence id.
    with tempfile.TemporaryDirectory(prefix="claudeagent-test-rp-") as tmp:
        initialize_agent_context({"cve_id": "CVE-TEST", "project": "curl"}, binary, "CVE-TEST", tmp, tmp)
        res = run_python("print('hello from run_python')", timeout_sec=30, max_output_chars=0)
        check("run_python ok", res.get("ok") is True)
        check("run_python has observation_id", bool(res.get("observation_id")))
        evs = res.get("evidence") or []
        check("run_python minted >=1 evidence", len(evs) >= 1)
        check("run_python stdout captured", "hello from run_python" in (res.get("stdout_head", "") + res.get("stdout_tail", "")))
        # The evidence id must be in the ledger.
        from claudeagent.runtime import evidence_ids_in_ledger
        eid = evs[0]["evidence_id"] if evs else None
        check("run_python evidence id in ledger", eid in evidence_ids_in_ledger())
        check(
            "run_python evidence starts pending and unseen",
            bool(evs)
            and evs[0].get("claim_status") == "pending"
            and evs[0].get("claim_source") == "host"
            and evs[0].get("host_claim") == evs[0].get("claim")
            and evs[0].get("returned_response_index") is None,
        )

    if failures:
        print("FAIL:", failures)
        return 1
    print("SANDBOX TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
