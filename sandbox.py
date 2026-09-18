"""bubblewrap-based OS sandbox for running untrusted model-authored Python.

The single inspection surface the model has is ``run_python``: it writes a
Python script and we execute it. An arbitrary Python process blows past the old
argv-level command policy (``open()`` of sibling debug binaries, arbitrary
``subprocess``, dynamic ``getattr`` dispatch -- static regex cannot see it).
Instead of auditing the script, we confine the *process* with bubblewrap:

  - new user / net / pid namespaces (unprivileged; ``unprivileged_userns_clone`` is on),
  - the target binary is the ONLY binary mounted (read-only, at a fixed in-sandbox path),
  - only ``/usr /lib /lib64 /bin`` are mounted read-only (python3 + binutils + loader),
  - ``scratch`` is writable (intermediate dumps), everything else (``/home /etc /root /tmp``,
    source repos, sibling debug artifacts) is simply absent. When debug mode is
    enabled, its symbols/DWARF have already been merged into the one mounted target,
  - network is unshared (no exfiltration).

So confinement is enforced by the OS, not by inspecting script text. The script
can still call ``objdump``/``readelf``/``strings`` on ``/workspace/binary`` and
do arbitrary arithmetic/parsing -- that is the intended freedom -- but it
physically cannot reach debug/source artifacts that the harness must never leak.

Return values mirror ``host.run_host_cmd`` so the observation pipeline is reused verbatim.
"""

from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path
from typing import Any

from claudeagent.host import run_host_cmd


SANDBOX_BINARY = "/workspace/binary"
SANDBOX_SCRATCH = "/scratch"


def _host_ro_binds() -> list[tuple[str, str]]:
    """Read-only host dirs the sandbox needs: python3, binutils, the loader."""
    binds: list[tuple[str, str]] = []
    for host_dir in ("/usr", "/lib", "/lib64", "/bin"):
        if os.path.isdir(host_dir):
            binds.append((host_dir, host_dir))
    return binds


def bwrap_argv(
    *,
    script_in_sandbox: str,
    scratch_dir: str,
    binary_path: str,
) -> list[str]:
    """Build the bwrap invocation that runs ``python3 -S <script>`` confined.

    ``script_in_sandbox`` must live under the sandbox-visible ``/scratch`` (i.e.
    the real ``scratch_dir`` is bind-mounted at ``/scratch``).
    """
    argv: list[str] = [
        "bwrap",
        "--unshare-user",
        "--unshare-net",
        "--unshare-pid",
        "--die-with-parent",
        "--new-session",
        "--setenv", "PYTHONPATH", "",   # drop external site-packages paths
        "--setenv", "HOME", SANDBOX_SCRATCH,  # keep python from writing pycache elsewhere
    ]
    for host_dir, sandbox_dir in _host_ro_binds():
        argv += ["--ro-bind", host_dir, sandbox_dir]
    argv += [
        "--ro-bind", str(Path(binary_path).resolve()), SANDBOX_BINARY,
        "--bind", str(Path(scratch_dir).resolve()), SANDBOX_SCRATCH,
        "--proc", "/proc",
        "--dev", "/dev",
        "/usr/bin/python3", "-S", script_in_sandbox,
    ]
    return argv


def run_in_sandbox(
    *,
    script_path: str,
    scratch_dir: str,
    binary_path: str,
    timeout: int = 240,
    max_output_chars: int | None = None,
) -> dict[str, Any]:
    """Run a script file (already written under ``scratch_dir``) confined.

    ``script_path`` is the host path; we translate it to its sandbox path under
    ``/scratch``. Returns a ``run_host_cmd``-shaped dict.
    """
    resolved_scratch = Path(scratch_dir).resolve()
    resolved_script = Path(script_path).resolve()
    try:
        relative_script = resolved_script.relative_to(resolved_scratch)
    except ValueError as exc:
        raise ValueError("script_path must resolve beneath scratch_dir") from exc
    script_in_sandbox = f"{SANDBOX_SCRATCH}/{relative_script.as_posix()}"
    argv = bwrap_argv(script_in_sandbox=script_in_sandbox, scratch_dir=scratch_dir, binary_path=binary_path)
    return run_host_cmd(argv, timeout=timeout, max_output_chars=max_output_chars)


def preflight_sandbox() -> dict[str, Any]:
    """Cheap liveness check: is bwrap usable in this environment?"""
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return {"ok": False, "error": "bwrap not found on PATH", "bwrap": None}
    # Run the smallest possible confined command. We still need a writable bind target.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="claudeagent-sandbox-preflight-") as tmp:
        argv = [
            "bwrap", "--unshare-user", "--unshare-net", "--unshare-pid",
            "--die-with-parent", "--new-session",
        ]
        for host_dir in ("/usr", "/lib", "/lib64", "/bin"):
            if os.path.isdir(host_dir):
                argv += ["--ro-bind", host_dir, host_dir]
        argv += ["--proc", "/proc", "--dev", "/dev", "--bind", tmp, SANDBOX_SCRATCH,
                 "/usr/bin/true"]
        result = run_host_cmd(argv, timeout=20)
    return {
        "ok": bool(result.get("ok")),
        "bwrap": bwrap,
        "returncode": result.get("returncode"),
        "stderr_tail": (result.get("stderr") or "")[-400:],
    }


def _smoke_test_main() -> int:
    """Ad-hoc self-check: write a probe script and run it confined. For manual/dev use."""
    import tempfile
    from claudeagent.common import jdump  # noqa: F401  (kept for pretty-print reuse)
    binary = os.environ.get("CLAUDEAGENT_SMOKE_BINARY", "/bin/ls")
    with tempfile.TemporaryDirectory(prefix="claudeagent-smoke-") as tmp:
        probe = (
            "import os, subprocess\n"
            "print('whoami ok')\n"
            "try:\n"
            "    open('/etc/passwd')\n"
            "    print('LEAK: /etc/passwd readable')\n"
            "except FileNotFoundError:\n"
            "    print('confined: /etc/passwd absent')\n"
            "try:\n"
            "    print('home listing:', os.listdir('/home'))\n"
            "except Exception as e:\n"
            "    print('confined: /home not visible:', repr(e))\n"
            "print('binary magic:', open('/workspace/binary','rb').read(4))\n"
            "print('readelf:', subprocess.run(['readelf','-h','/workspace/binary'],capture_output=True,text=True).returncode)\n"
            "open('/scratch/out.txt','w').write('scratch writable')\n"
        )
        sp = Path(tmp) / "probe.py"
        sp.write_text(probe)
        res = run_in_sandbox(script_path=str(sp), scratch_dir=tmp, binary_path=binary, timeout=30)
        print("returncode:", res.get("returncode"))
        print("stdout:", res.get("stdout"))
        print("stderr:", res.get("stderr"))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(_smoke_test_main())
