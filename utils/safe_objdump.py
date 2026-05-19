#!/usr/bin/env python3
"""Bounded objdump helper for Codex patch-presence runs.

The goal is to expose enough local binary evidence without dumping whole
functions or sections into the model context.
"""

from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys
from pathlib import Path


DEFAULT_WINDOW = 384
MAX_WINDOW = 4096
DEFAULT_CONTEXT = 4
MAX_CONTEXT = 16
DEFAULT_MAX_OUTPUT = 8192
MAX_OUTPUT = 65536


def parse_int(value: str) -> int:
    return int(value, 0)


def clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(value, upper))


def append_capped(chunks: list[str], text: str, state: dict[str, int], limit: int) -> bool:
    data = text.encode("utf-8", errors="replace")
    remaining = limit - state["bytes"]
    if remaining <= 0:
        return False
    if len(data) <= remaining:
        chunks.append(text)
        state["bytes"] += len(data)
        return True
    chunks.append(data[:remaining].decode("utf-8", errors="replace"))
    state["bytes"] = limit
    return False


def run_text(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr[-2000:]}")
    return proc.stdout


def load_symbols(binary: Path) -> list[tuple[int, str, str]]:
    out = run_text(["nm", "-an", str(binary)])
    symbols: list[tuple[int, str, str]] = []
    for line in out.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) != 3:
            continue
        addr_s, kind, name = parts
        if not re.fullmatch(r"[0-9a-fA-F]+", addr_s):
            continue
        if kind.lower() not in {"t", "w"}:
            continue
        symbols.append((int(addr_s, 16), kind, name))
    symbols.sort(key=lambda item: item[0])
    return symbols


def symbol_range(binary: Path, symbol: str, window: int) -> tuple[int, int, str]:
    symbols = load_symbols(binary)
    for index, (addr, _kind, name) in enumerate(symbols):
        if name == symbol:
            next_addr = symbols[index + 1][0] if index + 1 < len(symbols) else addr + window
            stop = min(next_addr, addr + window)
            return addr, max(addr + 1, stop), name
    sample = ", ".join(name for _addr, _kind, name in symbols[:20])
    raise SystemExit(f"symbol not found: {symbol}; first symbols: {sample}")


def objdump_range(binary: Path, start: int, stop: int, demangle: bool, line_numbers: bool) -> list[str]:
    cmd = ["objdump", "-d", "--no-show-raw-insn", f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}"]
    if demangle:
        cmd.append("--demangle")
    if line_numbers:
        cmd.append("--line-numbers")
    cmd.append(str(binary))
    return run_text(cmd).splitlines(keepends=True)


def objdump_stream(binary: Path, demangle: bool, line_numbers: bool):
    cmd = ["objdump", "-d", "--no-show-raw-insn"]
    if demangle:
        cmd.append("--demangle")
    if line_numbers:
        cmd.append("--line-numbers")
    cmd.append(str(binary))
    proc = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line
    stderr = proc.stderr.read() if proc.stderr is not None else ""
    rc = proc.wait()
    if rc != 0:
        raise SystemExit(f"command failed ({rc}): {' '.join(cmd)}\n{stderr[-2000:]}")


def filter_lines(lines, pattern: str, context: int, max_output: int) -> tuple[str, bool, int]:
    regex = re.compile(pattern)
    before: collections.deque[str] = collections.deque(maxlen=context)
    after = 0
    chunks: list[str] = []
    state = {"bytes": 0}
    matched = 0
    truncated = False

    for line in lines:
        hit = bool(regex.search(line))
        if hit:
            matched += 1
            if chunks and (not chunks[-1].endswith("--\n")):
                if not append_capped(chunks, "--\n", state, max_output):
                    truncated = True
                    break
            for old in before:
                if not append_capped(chunks, old, state, max_output):
                    truncated = True
                    break
            before.clear()
            if truncated:
                break
            if not append_capped(chunks, line, state, max_output):
                truncated = True
                break
            after = context
            continue

        if after > 0:
            if not append_capped(chunks, line, state, max_output):
                truncated = True
                break
            after -= 1
        else:
            before.append(line)

    return "".join(chunks), truncated, matched


def emit_with_cap(lines: list[str], max_output: int) -> bool:
    state = {"bytes": 0}
    truncated = False
    for line in lines:
        if not append_capped([], "", state, max_output):
            truncated = True
            break
        data = line.encode("utf-8", errors="replace")
        remaining = max_output - (state["bytes"] - 0)
        if len(data) > remaining:
            sys.stdout.write(data[:remaining].decode("utf-8", errors="replace"))
            state["bytes"] = max_output
            truncated = True
            break
        sys.stdout.write(line)
        state["bytes"] += len(data)
    return truncated


def main() -> int:
    parser = argparse.ArgumentParser(description="Run objdump with bounded output.")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--symbol", help="Disassemble a bounded window starting at this exact nm symbol.")
    parser.add_argument("--addr", type=parse_int, help="Disassemble around this address.")
    parser.add_argument("--window", type=parse_int, default=DEFAULT_WINDOW, help="Byte window for --symbol/--addr.")
    parser.add_argument("--grep", help="Regex filter. With no --symbol/--addr, scans disassembly and prints matches with context.")
    parser.add_argument("--context", type=int, default=DEFAULT_CONTEXT)
    parser.add_argument("--max-output-bytes", type=parse_int, default=DEFAULT_MAX_OUTPUT)
    parser.add_argument("--demangle", action="store_true")
    parser.add_argument("--line-numbers", action="store_true")
    args = parser.parse_args()

    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    if args.symbol and args.addr is not None:
        raise SystemExit("use only one of --symbol or --addr")
    if not args.symbol and args.addr is None and not args.grep:
        raise SystemExit("provide --symbol, --addr, or --grep")

    window = clamp(args.window, 1, MAX_WINDOW)
    context = clamp(args.context, 0, MAX_CONTEXT)
    max_output = clamp(args.max_output_bytes, 1024, MAX_OUTPUT)

    header: list[str] = []
    if args.symbol:
        start, stop, found = symbol_range(binary, args.symbol, window)
        header.append(f"# safe_objdump symbol={found} range=0x{start:x}:0x{stop:x} window={window}\n")
        lines = objdump_range(binary, start, stop, args.demangle, args.line_numbers)
    elif args.addr is not None:
        half = max(1, window // 2)
        start = max(0, args.addr - half)
        stop = args.addr + half
        header.append(f"# safe_objdump addr=0x{args.addr:x} range=0x{start:x}:0x{stop:x} window={window}\n")
        lines = objdump_range(binary, start, stop, args.demangle, args.line_numbers)
    else:
        header.append(f"# safe_objdump grep={args.grep!r} full-disassembly-scan context={context}\n")
        output, truncated, matched = filter_lines(
            objdump_stream(binary, args.demangle, args.line_numbers),
            args.grep,
            context,
            max_output,
        )
        sys.stdout.write("".join(header))
        sys.stdout.write(f"# matches={matched} max_output_bytes={max_output}\n")
        sys.stdout.write(output)
        if truncated:
            sys.stdout.write("\n# TRUNCATED: narrow --grep, reduce --context, or use --addr/--symbol.\n")
        return 0

    if args.grep:
        output, truncated, matched = filter_lines(lines, args.grep, context, max_output)
        sys.stdout.write("".join(header))
        sys.stdout.write(f"# matches={matched} max_output_bytes={max_output}\n")
        sys.stdout.write(output)
        if truncated:
            sys.stdout.write("\n# TRUNCATED: use a smaller --window/--context or a more specific --grep.\n")
        return 0

    sys.stdout.write("".join(header))
    truncated = emit_with_cap(lines, max_output)
    if truncated:
        sys.stdout.write("\n# TRUNCATED: use a smaller --window or add --grep.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
