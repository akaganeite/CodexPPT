from __future__ import annotations

import argparse
import json
import subprocess
import threading
import time
from pathlib import Path

from .io import is_relative_to


def run_codex(
    prompt: str,
    cve: str,
    args: argparse.Namespace,
    raw_dir: Path,
    schema_path: Path,
) -> tuple[int, str, str, Path]:
    last_message = raw_dir / f"{cve}.last.json"
    stdout_path = raw_dir / f"{cve}.stdout"
    stderr_path = raw_dir / f"{cve}.stderr"
    prompt_path = raw_dir / f"{cve}.prompt.txt"
    prompt_path.write_text(prompt, encoding="utf-8")

    cmd = [
        args.codex_bin,
        "exec",
        "--skip-git-repo-check",
        "--sandbox",
        args.sandbox,
        "--cd",
        str(args.cd),
        "--output-schema",
        str(schema_path),
        "--output-last-message",
        str(last_message),
    ]
    if not is_relative_to(args.target_dir, args.cd):
        cmd.extend(["--add-dir", str(args.target_dir)])
    if hasattr(args, "safe_objdump_dir") and not is_relative_to(args.safe_objdump_dir, args.cd):
        cmd.extend(["--add-dir", str(args.safe_objdump_dir)])
    if args.model:
        cmd.extend(["--model", args.model])
    if args.profile:
        cmd.extend(["--profile", args.profile])
    if args.codex_json_events:
        cmd.append("--json")
    cmd.append("-")

    started_at = time.time()
    started_monotonic = time.monotonic()
    proc, stdout, stderr, events = run_process_with_capture(
        cmd=cmd,
        stdin_text=prompt,
        timeout=args.timeout,
    )
    elapsed_seconds = time.monotonic() - started_monotonic
    write_timing(
        raw_dir / f"{cve}.timing.json",
        raw_dir / f"{cve}.timing.md",
        cve,
        cmd,
        started_at,
        elapsed_seconds,
        proc.returncode,
        events,
    )
    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")

    final_text = ""
    if last_message.exists():
        final_text = last_message.read_text(encoding="utf-8", errors="replace")
    if not final_text.strip():
        final_text = stdout
    return proc.returncode, final_text, stderr, last_message


def run_process_with_capture(
    cmd: list[str],
    stdin_text: str,
    timeout: int,
) -> tuple[subprocess.CompletedProcess[str], str, str, list[dict[str, object]]]:
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    events: list[dict[str, object]] = []

    def read_stdout() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            stdout_lines.append(line)
            events.append({"stream": "stdout", "time": time.time(), "line": line.rstrip("\n")})

    def read_stderr() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            stderr_lines.append(line)

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    try:
        assert proc.stdin is not None
        proc.stdin.write(stdin_text)
        proc.stdin.close()
        returncode = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        returncode = proc.wait()
        stderr_lines.append(f"\nprocess timed out after {timeout}s and was killed\n")
    finally:
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

    return (
        subprocess.CompletedProcess(cmd, returncode),
        "".join(stdout_lines),
        "".join(stderr_lines),
        events,
    )


def write_timing(
    json_path: Path,
    markdown_path: Path,
    cve: str,
    cmd: list[str],
    started_at: float,
    elapsed_seconds: float,
    returncode: int,
    events: list[dict[str, object]],
) -> None:
    command_items = summarize_command_events(events)
    turns = summarize_turn_events(events)
    payload = {
        "cve": cve,
        "started_at_epoch": started_at,
        "elapsed_seconds": elapsed_seconds,
        "returncode": returncode,
        "command": cmd,
        "turns": turns,
        "command_executions": command_items,
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_path.write_text(render_timing_markdown(payload), encoding="utf-8")


def summarize_command_events(events: list[dict[str, object]]) -> list[dict[str, object]]:
    active: dict[str, dict[str, object]] = {}
    completed: list[dict[str, object]] = []
    for event in events:
        line = event.get("line")
        if not isinstance(line, str):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = obj.get("item")
        if not isinstance(item, dict) or item.get("type") != "command_execution":
            continue
        item_id = str(item.get("id", ""))
        event_type = obj.get("type")
        timestamp = float(event["time"])
        if event_type == "item.started":
            active[item_id] = {
                "id": item_id,
                "command": str(item.get("command", "")),
                "started_at_epoch": timestamp,
            }
        elif event_type == "item.completed":
            current = active.pop(
                item_id,
                {
                    "id": item_id,
                    "command": str(item.get("command", "")),
                    "started_at_epoch": timestamp,
                },
            )
            current["completed_at_epoch"] = timestamp
            current["elapsed_seconds"] = timestamp - float(current["started_at_epoch"])
            current["exit_code"] = item.get("exit_code")
            output = str(item.get("aggregated_output", ""))
            current["output_bytes"] = len(output.encode("utf-8", errors="replace"))
            completed.append(current)
    completed.sort(key=lambda row: float(row.get("elapsed_seconds", 0)), reverse=True)
    return completed


def summarize_turn_events(events: list[dict[str, object]]) -> list[dict[str, object]]:
    turns: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for event in events:
        line = event.get("line")
        if not isinstance(line, str):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        event_type = obj.get("type")
        timestamp = float(event["time"])
        if event_type == "turn.started":
            current = {"started_at_epoch": timestamp}
        elif event_type == "turn.completed":
            if current is None:
                current = {"started_at_epoch": timestamp}
            current["completed_at_epoch"] = timestamp
            current["elapsed_seconds"] = timestamp - float(current["started_at_epoch"])
            current["usage"] = obj.get("usage", {})
            turns.append(current)
            current = None
    return turns


def render_timing_markdown(payload: dict[str, object]) -> str:
    rows = payload["command_executions"]
    turns = payload.get("turns", [])
    assert isinstance(rows, list)
    assert isinstance(turns, list)
    total = float(payload["elapsed_seconds"])
    lines = [
        f"# Codex Exec Timing: {payload['cve']}",
        "",
        f"Total wall time: {total:.3f}s",
        f"Return code: {payload['returncode']}",
        "",
        "## Turns",
        "",
        "| Turn | Duration (s) | Input Tokens | Cached Input | Output Tokens | Reasoning Tokens |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for index, turn in enumerate(turns, 1):
        assert isinstance(turn, dict)
        usage = turn.get("usage", {})
        usage = usage if isinstance(usage, dict) else {}
        lines.append(
            f"| {index} | {float(turn.get('elapsed_seconds', 0)):.3f} | "
            f"{usage.get('input_tokens', '')} | {usage.get('cached_input_tokens', '')} | "
            f"{usage.get('output_tokens', '')} | {usage.get('reasoning_output_tokens', '')} |"
        )
    if not turns:
        lines.append("|  |  |  |  |  |  |")
    lines.extend(
        [
            "",
            "## Command Executions",
            "",
        "| Rank | Duration (s) | Exit | Output Bytes | Command |",
        "|---:|---:|---:|---:|---|",
        ]
    )
    for index, row in enumerate(rows, 1):
        assert isinstance(row, dict)
        command = str(row.get("command", "")).replace("|", "\\|")
        lines.append(
            f"| {index} | {float(row.get('elapsed_seconds', 0)):.3f} | "
            f"{row.get('exit_code', '')} | {row.get('output_bytes', 0)} | `{command}` |"
        )
    lines.append("")
    return "\n".join(lines)
