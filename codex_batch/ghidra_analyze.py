"""One-shot PyGhidra analyzer used by the host-side cache manager."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .io import write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cache-entry", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--install-dir", type=Path)
    return parser.parse_args()


def start_pyghidra(install_dir: Path | None) -> None:
    import pyghidra  # type: ignore

    if install_dir is None:
        pyghidra.start()
    else:
        pyghidra.start(install_dir=str(install_dir))


def analyze(binary: Path, cache_entry: Path, install_dir: Path | None) -> dict[str, Any]:
    import pyghidra  # type: ignore

    start_pyghidra(install_dir)
    project_dir = cache_entry / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    functions: list[dict[str, Any]] = []
    strings: list[dict[str, Any]] = []
    callgraph: dict[str, list[str]] = {}
    xrefs: dict[str, list[str]] = {}

    with pyghidra.open_program(
        str(binary),
        project_location=str(project_dir),
        project_name="project",
        analyze=True,
        program_name="target_binary",
    ) as api:
        program = api.getCurrentProgram()
        listing = program.getListing()
        function_manager = program.getFunctionManager()
        references = program.getReferenceManager()

        for function in function_manager.getFunctions(True):
            entry = str(function.getEntryPoint())
            body_ranges = [
                {"start": str(item.getMinAddress()), "end": str(item.getMaxAddress())}
                for item in function.getBody().getAddressRanges()
            ][:8]
            callees: set[str] = set()
            instruction_count = 0
            for instruction in listing.getInstructions(function.getBody(), True):
                instruction_count += 1
                if instruction_count > 5000:
                    break
                for reference in references.getReferencesFrom(instruction.getAddress()):
                    try:
                        if reference.getReferenceType().isCall():
                            target = reference.getToAddress()
                            target_function = function_manager.getFunctionContaining(target)
                            callees.add(str(target_function.getEntryPoint()) if target_function else str(target))
                    except Exception:
                        continue
            callgraph[entry] = sorted(callees)[:100]
            functions.append(
                {
                    "entry": entry,
                    "name": str(function.getName()),
                    "body_ranges": body_ranges,
                    "instruction_count_sampled": instruction_count,
                    "callees_sample": sorted(callees)[:20],
                }
            )

        try:
            for data in listing.getDefinedData(True):
                if len(strings) >= 5000:
                    break
                try:
                    value = data.getValue()
                    if value is not None and "string" in str(data.getDataType()).lower():
                        strings.append({"address": str(data.getAddress()), "value": str(value)[:300]})
                except Exception:
                    continue
        except Exception:
            pass

    for caller, callees in callgraph.items():
        for callee in callees:
            xrefs.setdefault(callee, []).append(caller)

    write_json(cache_entry / "functions.json", functions)
    write_json(cache_entry / "strings.json", strings)
    write_json(cache_entry / "callgraph.json", callgraph)
    write_json(cache_entry / "xrefs.json", xrefs)
    return {
        "function_count": len(functions),
        "string_count": len(strings),
        "callgraph_edges": sum(len(items) for items in callgraph.values()),
    }


def main() -> int:
    args = parse_args()
    summary = analyze(
        args.binary.expanduser().resolve(),
        args.cache_entry.expanduser().resolve(),
        args.install_dir.expanduser().resolve() if args.install_dir is not None else None,
    )
    write_json(args.summary.expanduser().resolve(), summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
