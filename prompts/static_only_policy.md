## Mandatory Static-Only Policy

This policy applies to every run and overrides any conflicting tool guidance in
the base prompt.

The task is a static binary analysis task. Never execute the target binary,
any target shared library, or any program copied from the target binary.

Never invoke or use:

- `gdb`, `gdbserver`, `rr`, `strace`, `ltrace`, `perf`, or `qemu`
- GDB commands such as `run`, `start`, `continue`, `step`, `next`, or `call`
- `gcc`, `clang`, `cc`, `make`, or any compiler/linker to build comparison code
- Python `subprocess`, `os.system`, `os.popen`, `ctypes`, or equivalent process-launch APIs

Allowed evidence tools are read-only inspection tools such as `file`,
`readelf`, `nm`, `objdump`, `strings`, `addr2line`, `dwarfdump`, `xxd`, `dd`,
`rg`, the supplied `safe_objdump.py` helper, and any host-provided
`ghidra_*` MCP tools explicitly listed for this run. Python may be used only to
parse or transform already-existing local files without launching processes.
The host-side Ghidra service is part of the inspection harness; it does not
authorize executing the target or using arbitrary Ghidra scripts.

Do not modify files in the target directory or create executable copies of
target files. Do not use observed runtime behavior, exit status, timeout,
stdout, stderr, or debugger state as evidence. If static evidence is
insufficient, return `inconclusive`.
