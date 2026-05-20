#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Append a compact run summary for Feishu sync.")
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--cve", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument(
        "--summary-file",
        type=Path,
        default=Path("runs") / "codex-ppt-results-summarized.md",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"expected JSON object: {path}")
    return data


def markdown_table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")
    return lines


def format_float(value: object) -> str:
    if isinstance(value, int | float):
        return f"{value:.4f}"
    return ""


def build_section(run_dir: Path, cve: str, title: str) -> str:
    metrics_path = run_dir / "results.json.metrics.json"
    timing_path = run_dir / "raw" / f"{cve}.timing.json"
    if not metrics_path.is_file():
        raise SystemExit(f"metrics file not found: {metrics_path}")
    if not timing_path.is_file():
        raise SystemExit(f"timing file not found: {timing_path}")

    metrics_payload = load_json(metrics_path)
    timing_payload = load_json(timing_path)
    metrics = metrics_payload.get("metrics", {})
    counts = metrics_payload.get("counts", {})
    turns = timing_payload.get("turns", [])
    commands = timing_payload.get("command_executions", [])
    if not isinstance(metrics, dict) or not isinstance(counts, dict):
        raise SystemExit(f"invalid metrics payload: {metrics_path}")
    if not isinstance(turns, list) or not isinstance(commands, list):
        raise SystemExit(f"invalid timing payload: {timing_path}")

    tool_calls = len(commands)
    cmd_output_bytes = sum(int(row.get("output_bytes", 0)) for row in commands if isinstance(row, dict))
    elapsed = float(timing_payload.get("elapsed_seconds", 0))

    lines: list[str] = [
        f"# {title}",
        "",
        f"- run_dir: `{run_dir}`",
        f"- cve: `{cve}`",
        f"- wall_time_seconds: `{elapsed:.3f}`",
        "",
        "## metrics",
        "",
    ]
    lines.extend(
        markdown_table(
            ["A", "P", "R", "F1", "DSR", "TP", "TN", "FP", "FN", "TC", "Inconclusive", "Error"],
            [
                [
                    format_float(metrics.get("A")),
                    format_float(metrics.get("P")),
                    format_float(metrics.get("R")),
                    format_float(metrics.get("F1")),
                    format_float(metrics.get("DSR")),
                    counts.get("TP", ""),
                    counts.get("TN", ""),
                    counts.get("FP", ""),
                    counts.get("FN", ""),
                    counts.get("TC", ""),
                    counts.get("inconclusive", ""),
                    counts.get("error", ""),
                ]
            ],
        )
    )
    lines.extend(["", "## turns", ""])
    lines.extend(
        markdown_table(
            [
                "Turn",
                "Duration (s)",
                "Input Tokens",
                "Cached Input",
                "Output Tokens",
                "Reasoning Tokens",
                "Tool Calls",
                "Cmd Output Bytes",
            ],
            [
                [
                    index,
                    f"{float(turn.get('elapsed_seconds', 0)):.3f}" if isinstance(turn, dict) else "",
                    (turn.get("usage", {}) if isinstance(turn, dict) else {}).get("input_tokens", ""),
                    (turn.get("usage", {}) if isinstance(turn, dict) else {}).get("cached_input_tokens", ""),
                    (turn.get("usage", {}) if isinstance(turn, dict) else {}).get("output_tokens", ""),
                    (turn.get("usage", {}) if isinstance(turn, dict) else {}).get("reasoning_output_tokens", ""),
                    tool_calls,
                    cmd_output_bytes,
                ]
                for index, turn in enumerate(turns, 1)
            ],
        )
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    section = build_section(args.run_dir, args.cve, args.title)
    args.summary_file.parent.mkdir(parents=True, exist_ok=True)
    if args.summary_file.exists() and args.summary_file.stat().st_size > 0:
        with args.summary_file.open("a", encoding="utf-8") as f:
            f.write("\n")
            f.write(section)
            f.write("\n")
    else:
        args.summary_file.write_text(section + "\n", encoding="utf-8")
    print(args.summary_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
