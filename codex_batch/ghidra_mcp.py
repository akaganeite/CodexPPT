"""Stdio MCP server exposing six bounded, read-only Ghidra tools."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import ghidra_tools


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-entry", type=Path, required=True)
    parser.add_argument("--query-log", type=Path, required=True)
    parser.add_argument("--install-dir", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    return parser.parse_args()


def validate_cache_entry(cache_entry: Path) -> None:
    if len(cache_entry.name) != 64 or any(ch not in "0123456789abcdef" for ch in cache_entry.name):
        raise ValueError("Ghidra MCP cache entry must be named by a SHA256 digest")
    meta_path = cache_entry / "analysis_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("status") != "ready" or meta.get("binary_sha256") != cache_entry.name:
        raise ValueError("Ghidra MCP cache entry is not ready")
    if not (cache_entry / "target_binary").is_file() or not (cache_entry / "project").is_dir():
        raise ValueError("Ghidra MCP cache entry is incomplete")


def build_server():
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(
        "straight_detect_ghidra",
        description="Bounded static Ghidra inspection for one anonymous target_binary.",
        instructions=(
            "Use raw instructions, CFG, and P-code as evidence. Recovered decompiler text is advisory "
            "and cannot be the sole basis for a determinate patch-presence verdict."
        ),
    )
    server.add_tool(
        ghidra_tools.ghidra_locate_function,
        description=(
            "Rank candidate functions using strings, callees, constants, and field offsets. "
            "Verify candidates with raw instruction or CFG tools."
        ),
        structured_output=True,
    )
    server.add_tool(
        ghidra_tools.ghidra_function_summary,
        description="Return bounded function ranges, calls, branches, returns, constants, and raw instructions.",
        structured_output=True,
    )
    server.add_tool(
        ghidra_tools.ghidra_cfg_slice,
        description="Return bounded basic blocks, edges, and raw instructions around an address.",
        structured_output=True,
    )
    server.add_tool(
        ghidra_tools.ghidra_path_probe,
        description="Probe bounded local CFG paths and required or forbidden instruction patterns.",
        structured_output=True,
    )
    server.add_tool(
        ghidra_tools.ghidra_call_args,
        description="Return a call instruction, nearby setup instructions, callee, and P-code.",
        structured_output=True,
    )
    server.add_tool(
        ghidra_tools.ghidra_decompile_slice,
        description="Return advisory pseudocode plus the corresponding raw instruction window.",
        structured_output=True,
    )
    return server


def main() -> int:
    args = parse_args()
    cache_entry = args.cache_entry.expanduser().resolve()
    validate_cache_entry(cache_entry)
    ghidra_tools.configure_runtime(
        cache_entry,
        args.install_dir,
        args.query_log,
        args.timeout,
    )
    build_server().run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
