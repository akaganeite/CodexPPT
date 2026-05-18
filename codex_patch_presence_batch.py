#!/usr/bin/env python3
"""
Run one `codex exec` patch-presence analysis per CVE and merge the results.

Input:
  - project JSON: CVE metadata, e.g. binutils.json
  - testset JSON: CVE -> list of requested binaries
  - target dir: directory containing binaries

Each Codex invocation receives exactly one CVE, its metadata, and the binary
list for that CVE. The script saves raw per-CVE outputs and writes one merged
JSON result.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


STATUS_VALUES = {"present", "absent", "inconclusive", "not_found", "error"}
VERSION_RE = re.compile(r"^binutils-([0-9]+(?:\.[0-9]+){1,2})-(?:objdump|readelf|nm)$")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    tmp.replace(path)


def requested_binary_to_actual(name: str, opt: str = "o0") -> str:
    for tool in ("readelf", "objdump", "nm"):
        suffix = "-" + tool
        if name.endswith(suffix):
            return name[: -len(suffix)] + "-" + opt + suffix
    return name


def is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def derive_project_paths(args: argparse.Namespace) -> None:
    """Fill project_json/testset_json/target_dir/output from --project when used."""
    base_dir = args.base_dir.resolve()
    binaries_root = args.binaries_root.resolve()
    args.project_dir = None
    if args.project:
        project = args.project
        project_dir = base_dir / project
        args.project_dir = project_dir

        project_json_candidates = [project_dir / f"{project}.json", base_dir / f"{project}.json"]
        testset_candidates = [project_dir / "testset.json", base_dir / "testset.json"]
        target_candidates = [
            binaries_root / f"{project}_gcc",
            project_dir / "targets",
            project_dir / "gcc",
            project_dir,
        ]

        if args.project_json is None:
            args.project_json = next((p for p in project_json_candidates if p.exists()), project_json_candidates[0])
        if args.testset_json is None:
            args.testset_json = next((p for p in testset_candidates if p.exists()), testset_candidates[0])
        if args.target_dir is None:
            args.target_dir = next((p for p in target_candidates if p.exists()), target_candidates[0])
        if args.output is None:
            args.output = project_dir / f"{project}_{args.opt}_codex_results.json"

    missing = [
        name
        for name in ("project_json", "testset_json", "target_dir", "output")
        if getattr(args, name) is None
    ]
    if missing:
        opts = ", ".join("--" + name.replace("_", "-") for name in missing)
        raise ValueError(f"missing required arguments: {opts}; or provide --project")


def normalize_testset(raw: Any) -> dict[str, list[str]]:
    """Accept the original CVE -> [binaries] format.

    A ground-truth style CVE -> {vuln, patch} file is intentionally rejected:
    detection needs concrete binary names, not labels.
    """
    if not isinstance(raw, dict):
        raise ValueError("testset JSON must be an object: CVE -> list[binary]")

    out: dict[str, list[str]] = {}
    bad: list[str] = []
    for cve, value in raw.items():
        if isinstance(value, list) and all(isinstance(x, str) for x in value):
            out[str(cve)] = value
        else:
            bad.append(str(cve))
    if bad:
        sample = ", ".join(bad[:5])
        raise ValueError(
            "testset JSON must map each CVE to a list of binary names. "
            f"Non-list entries include: {sample}"
        )
    return out


def evaluate_results(results: dict[str, Any], groundtruth: dict[str, Any]) -> dict[str, Any]:
    """Evaluate merged results against CVE -> {vuln, patch} groundtruth.

    not_found is excluded from TC. inconclusive and error are counted in TC, but
    not in the Accuracy denominator, matching the table definition supplied by
    the user.
    """
    counts = {
        "TP": 0,
        "TN": 0,
        "FP": 0,
        "FN": 0,
        "inconclusive": 0,
        "error": 0,
        "not_found": 0,
        "version_not_in_groundtruth": 0,
        "missing_groundtruth_cve": 0,
    }
    mismatches: list[dict[str, str]] = []

    for cve, per_binary in results.items():
        gt = groundtruth.get(cve)
        if not isinstance(gt, dict):
            counts["missing_groundtruth_cve"] += len(per_binary)
            continue
        patched = {str(x) for x in gt.get("patch", [])}
        vulnerable = {str(x) for x in gt.get("vuln", [])}

        for binary, row in per_binary.items():
            match = VERSION_RE.match(binary)
            if not match:
                counts["version_not_in_groundtruth"] += 1
                continue
            version = match.group(1)
            if version in patched:
                expected = "present"
            elif version in vulnerable:
                expected = "absent"
            else:
                counts["version_not_in_groundtruth"] += 1
                continue

            status = str(row.get("status", "error")) if isinstance(row, dict) else "error"
            if status == "not_found":
                counts["not_found"] += 1
                continue
            if status == "inconclusive":
                counts["inconclusive"] += 1
                continue
            if status == "error":
                counts["error"] += 1
                continue

            if expected == "present" and status == "present":
                counts["TP"] += 1
            elif expected == "absent" and status == "absent":
                counts["TN"] += 1
            elif expected == "absent" and status == "present":
                counts["FP"] += 1
                mismatches.append({"cve": cve, "binary": binary, "expected": expected, "predicted": status})
            elif expected == "present" and status == "absent":
                counts["FN"] += 1
                mismatches.append({"cve": cve, "binary": binary, "expected": expected, "predicted": status})
            else:
                counts["error"] += 1

    tp = counts["TP"]
    tn = counts["TN"]
    fp = counts["FP"]
    fn = counts["FN"]
    undecided = counts["inconclusive"] + counts["error"]
    accuracy_den = tp + tn + fp + fn
    tc = accuracy_den + undecided

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / accuracy_den if accuracy_den else 0.0
    dsr = (tp + tn) / tc if tc else 0.0

    return {
        "counts": {
            **counts,
            "TC": tc,
            "accuracy_denominator": accuracy_den,
        },
        "metrics": {
            "P": precision,
            "R": recall,
            "F1": f1,
            "A": accuracy,
            "DSR": dsr,
        },
        "mismatches": mismatches,
    }


def build_prompt(
    cve: str,
    metadata: Any,
    binaries: list[str],
    target_dir: Path,
    opt: str,
) -> str:
    actual_map = {b: requested_binary_to_actual(b, opt) for b in binaries}
    payload = {
        "cve": cve,
        "metadata": metadata,
        "requested_binaries": binaries,
        "binary_resolution": actual_map,
        "target_dir": str(target_dir),
        "optimization": opt,
    }

    return (
        "You are doing an authorized local patch-presence evaluation.\n"
        "Analyze exactly one CVE across the requested binaries.\n\n"
        "Hard rules:\n"
        "1. Do not use the network.\n"
        "2. Do not use version-number matching as evidence.\n"
        "3. Use only local binary evidence and the supplied metadata: symbols, "
        "strings, disassembly, DWARF line info, calls, branches, constants, and "
        "control-flow/guard differences.\n"
        "4. Do not open, read, cat, sed, grep, or otherwise inspect source files "
        "referenced by DWARF/debug info paths, diff file paths, or absolute paths "
        "inside metadata. The metadata JSON included in this prompt is the only "
        "source-like context you may use.\n"
        "5. You may use line/file annotations printed by binary tools such as "
        "objdump --line-numbers, because those annotations come from the binary's "
        "debug info. Do not follow those paths to read the actual source files.\n"
        "6. If the resolved binary file does not exist under target_dir, return "
        "status not_found for that requested binary.\n"
        "7. If evidence is not decisive, return inconclusive. Do not guess.\n"
        "8. Final response must be valid JSON only, with no markdown fences.\n\n"
        "Tool-output budget rules:\n"
        "- Prefer `nm`, `strings`, `readelf`, and narrowly filtered commands to "
        "locate evidence before disassembly.\n"
        "- For disassembly, use the bounded helper available in the working "
        "directory: `python3 safe_objdump.py --binary PATH ...`.\n"
        "- `safe_objdump.py` supports `--symbol SYMBOL`, `--addr 0xADDR`, "
        "`--window BYTES`, `--grep REGEX`, `--context N`, `--demangle`, and "
        "`--line-numbers`. Default output is capped at 8 KiB; keep caps unless "
        "a small increase is essential.\n"
        "- Start with `--grep` plus small `--context` values. Use `--window` "
        "only after you know the relevant function or address; normally keep "
        "`--window` at or below 1024 bytes and `--context` at or below 4.\n"
        "- Do not run naked `objdump` over an entire section, entire large "
        "function, or broad address range. Any raw objdump output must be "
        "limited to at most 120 lines or 8 KiB. If more is needed, narrow the "
        "address range or grep pattern instead.\n"
        "- Disassembly call budget: at most 2 `safe_objdump.py` calls per "
        "requested binary, and at most 10 total disassembly calls for the CVE. "
        "Count raw `objdump` as a disassembly call too.\n"
        "- If you cannot reach decisive evidence inside that budget, return "
        "inconclusive for the affected binary instead of continuing exploration.\n"
        "- Reuse evidence across binaries when the same symbol and pattern are "
        "being checked; do not repeat broad scans for every binary.\n"
        "- Avoid repeated exploration: once you have decisive local evidence for "
        "a binary, stop inspecting that binary.\n\n"
        "Status semantics:\n"
        "- present: patch is present in the binary.\n"
        "- absent: patch is absent / vulnerable-side behavior is present.\n"
        "- inconclusive: binary exists but evidence is insufficient.\n"
        "- not_found: resolved binary file is missing.\n\n"
        "Required JSON shape:\n"
        "{\n"
        '  "results": [\n'
        "    {\n"
        '      "cve": "CVE-ID",\n'
        '      "binary": "requested-binary-name",\n'
        '      "status": "present|absent|inconclusive|not_found",\n'
        '      "confidence": "high|medium|low",\n'
        '      "evidence": ["concise concrete evidence"],\n'
        '      "reasoning": "brief logical explanation"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Task payload JSON:\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=False)}\n"
    )


def extract_json_object(text: str) -> Any:
    text = text.strip()
    if not text:
        raise ValueError("empty model output")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fence = re.search(r"```(?:json|js)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        return json.loads(fence.group(1))

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError("could not find a JSON object in model output")


def validate_cve_result(cve: str, binaries: list[str], obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("result root is not an object")

    if isinstance(obj.get("results"), list):
        per_binary = {
            str(row.get("binary")): row
            for row in obj["results"]
            if isinstance(row, dict) and str(row.get("cve", cve)) == cve
        }
    elif cve in obj and isinstance(obj[cve], dict):
        per_binary = obj[cve]
    else:
        # Be permissive if the model returns the per-binary object directly.
        per_binary = obj

    out: dict[str, Any] = {}
    for binary in binaries:
        row = per_binary.get(binary)
        if not isinstance(row, dict):
            out[binary] = {
                "status": "error",
                "confidence": "low",
                "evidence": ["codex output did not contain this requested binary"],
                "reasoning": "Missing per-binary result in final JSON.",
            }
            continue

        status = str(row.get("status", "error"))
        if status not in STATUS_VALUES:
            status = "error"

        evidence = row.get("evidence", [])
        if isinstance(evidence, str):
            evidence = [evidence]
        if not isinstance(evidence, list):
            evidence = [repr(evidence)]

        out[binary] = {
            "status": status,
            "confidence": str(row.get("confidence", "low")),
            "evidence": [str(x) for x in evidence],
            "reasoning": str(row.get("reasoning", "")),
        }
    return out


def cve_has_status(result: Any, status: str) -> bool:
    if not isinstance(result, dict):
        return False
    return any(isinstance(row, dict) and row.get("status") == status for row in result.values())


def write_schema(path: Path) -> None:
    schema = {
        "type": "object",
        "required": ["results"],
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["cve", "binary", "status", "confidence", "evidence", "reasoning"],
                    "properties": {
                        "cve": {"type": "string"},
                        "binary": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": ["present", "absent", "inconclusive", "not_found"],
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["high", "medium", "low"],
                        },
                        "evidence": {"type": "array", "items": {"type": "string"}},
                        "reasoning": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
        },
        "additionalProperties": False,
    }
    write_json(path, schema)


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
    if args.model:
        cmd.extend(["--model", args.model])
    if args.profile:
        cmd.extend(["--profile", args.profile])
    if args.codex_json_events:
        cmd.append("--json")
    cmd.append("-")

    proc = subprocess.run(
        cmd,
        input=prompt,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=args.timeout,
        check=False,
    )
    stdout_path.write_text(proc.stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(proc.stderr, encoding="utf-8", errors="replace")

    final_text = ""
    if last_message.exists():
        final_text = last_message.read_text(encoding="utf-8", errors="replace")
    if not final_text.strip():
        final_text = proc.stdout
    return proc.returncode, final_text, proc.stderr, last_message


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one codex exec per CVE and merge patch-presence JSON results."
    )
    parser.add_argument(
        "--project",
        help="Project name under --base-dir. Example: --project binutils uses binutils.json and binutils/.",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory containing <project>.json, testset.json, and <project>/.",
    )
    parser.add_argument(
        "--binaries-root",
        type=Path,
        default=Path.home() / "ClawSpace" / "binaries",
        help="Root for external binary collections. With --project binutils, the first default target-dir candidate is <root>/binutils_gcc.",
    )
    parser.add_argument(
        "--opt",
        default="o0",
        choices=["o0", "o1", "o2", "o3"],
        help="Optimization level used in target binary names, e.g. binutils-2.30-o2-objdump.",
    )
    parser.add_argument("--project-json", type=Path)
    parser.add_argument("--testset-json", type=Path)
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--groundtruth-json",
        type=Path,
        help="Groundtruth JSON used only by this wrapper after all codex exec runs finish. Never passed to codex.",
    )
    parser.add_argument(
        "--metrics-output",
        type=Path,
        help="Optional path for evaluation metrics JSON. Defaults to <output>.metrics.json.",
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=None,
        help="Directory for prompts, stdout/stderr, and per-CVE outputs.",
    )
    parser.add_argument("--cve", action="append", help="Only run this CVE; repeatable.")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--resume", action="store_true", help="Skip CVEs already in --output.")
    parser.add_argument(
        "--retry-errors",
        action="store_true",
        help="With --resume, rerun CVEs whose existing output contains at least one status=error.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Write prompts but do not call codex.")
    parser.add_argument("--codex-bin", default="codex")
    parser.add_argument("--model", default=None)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--sandbox", default="workspace-write", choices=["read-only", "workspace-write", "danger-full-access"])
    parser.add_argument(
        "--cd",
        type=Path,
        default=None,
        help="Working root passed to codex exec. With --project, defaults to the project directory; otherwise defaults to --target-dir.",
    )
    parser.add_argument(
        "--codex-json-events",
        action="store_true",
        help="Pass --json to codex exec. The final message is still read from --output-last-message.",
    )
    args = parser.parse_args()

    derive_project_paths(args)
    project_json = args.project_json.resolve()
    testset_json = args.testset_json.resolve()
    target_dir = args.target_dir.resolve()
    args.target_dir = target_dir
    output = args.output.resolve()
    raw_dir = (args.raw_dir or output.parent / (output.stem + "_codex_runs")).resolve()
    default_cd = args.project_dir if args.project_dir is not None else target_dir
    args.cd = (args.cd.resolve() if args.cd is not None else default_cd.resolve())
    groundtruth_json = args.groundtruth_json.resolve() if args.groundtruth_json else None
    metrics_output = (
        args.metrics_output.resolve()
        if args.metrics_output
        else output.with_suffix(output.suffix + ".metrics.json")
    )

    if groundtruth_json is not None:
        # The groundtruth must not be visible to codex exec. The wrapper reads it
        # only after model outputs have been merged.
        forbidden_roots = [target_dir, args.cd]
        if any(is_relative_to(groundtruth_json, root) for root in forbidden_roots):
            raise ValueError(
                "groundtruth JSON is inside the codex-visible target/cd directory. "
                "Move it outside the project directory before running."
            )

    if not target_dir.is_dir():
        raise ValueError(f"target directory does not exist or is not a directory: {target_dir}")

    metadata = load_json(project_json)
    testset = normalize_testset(load_json(testset_json))
    if not isinstance(metadata, dict):
        raise ValueError("project JSON must be an object keyed by CVE")

    selected = sorted(testset)
    if args.cve:
        wanted = set(args.cve)
        selected = [cve for cve in selected if cve in wanted]
    if args.limit is not None:
        selected = selected[: args.limit]

    existing: dict[str, Any] = {}
    if args.resume and output.exists():
        existing = load_json(output)
        if not isinstance(existing, dict):
            raise ValueError("--output exists but is not a JSON object")

    raw_dir.mkdir(parents=True, exist_ok=True)
    schema_path = raw_dir / "single_cve_schema.json"
    write_schema(schema_path)

    merged = dict(existing)
    for index, cve in enumerate(selected, 1):
        if args.resume and cve in merged:
            if args.retry_errors and cve_has_status(merged[cve], "error"):
                print(f"[{index}/{len(selected)}] retry {cve} (existing status=error)")
            else:
                print(f"[{index}/{len(selected)}] skip {cve} (already in output)")
                continue
        if cve not in metadata:
            merged[cve] = {
                binary: {
                    "status": "error",
                    "confidence": "low",
                    "evidence": [f"{cve} not found in project metadata JSON"],
                    "reasoning": "Cannot inspect patch presence without metadata.",
                }
                for binary in testset[cve]
            }
            write_json(output, merged)
            continue

        prompt = build_prompt(cve, metadata[cve], testset[cve], target_dir, args.opt)
        prompt_path = raw_dir / f"{cve}.prompt.txt"
        prompt_path.write_text(prompt, encoding="utf-8")

        print(f"[{index}/{len(selected)}] run {cve} ({len(testset[cve])} binaries)")
        if args.dry_run:
            continue

        try:
            rc, final_text, stderr_text, _ = run_codex(prompt, cve, args, raw_dir, schema_path)
            if rc != 0:
                raise RuntimeError(f"codex exec exited {rc}: {stderr_text[-1000:]}")
            parsed = extract_json_object(final_text)
            merged[cve] = validate_cve_result(cve, testset[cve], parsed)
        except Exception as exc:
            merged[cve] = {
                binary: {
                    "status": "error",
                    "confidence": "low",
                    "evidence": [f"codex exec failed or returned invalid JSON: {exc}"],
                    "reasoning": "See raw per-CVE files in raw_dir.",
                }
                for binary in testset[cve]
            }
        write_json(output, merged)

    if args.dry_run:
        print(f"dry-run complete; prompts written under {raw_dir}")
    else:
        print(f"merged results written to {output}")
        print(f"raw per-CVE files written under {raw_dir}")
        if groundtruth_json is not None:
            metrics = evaluate_results(merged, load_json(groundtruth_json))
            write_json(metrics_output, metrics)
            m = metrics["metrics"]
            c = metrics["counts"]
            print(f"metrics written to {metrics_output}")
            print(
                "metrics: "
                f"A={m['A']:.4f} P={m['P']:.4f} R={m['R']:.4f} "
                f"F1={m['F1']:.4f} DSR={m['DSR']:.4f} "
                f"(TP={c['TP']} TN={c['TN']} FP={c['FP']} FN={c['FN']} "
                f"inconclusive={c['inconclusive']} error={c['error']} "
                f"TC={c['TC']} not_found_excluded={c['not_found']})"
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
