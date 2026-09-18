from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from ..config import ElfRules
from ..system_utils import run_command


def tool_env() -> dict[str, str]:
    return {**os.environ, "LC_ALL": "C", "LANG": "C"}


@dataclass(frozen=True)
class SymbolInfo:
    name: str
    address: int
    kind: str


@dataclass(frozen=True)
class DwarfRecord:
    name: str
    kind: str
    tag: str
    die_offset: str
    origin_offset: str = ""
    low_pc: str = ""
    high_pc: str = ""
    ranges: str = ""
    entry_pc: str = ""


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def read_build_id(path: Path) -> str:
    proc = run_command(["readelf", "-n", str(path)], timeout=60, env=tool_env())
    if proc.returncode != 0:
        return ""
    match = re.search(r"Build ID:\s*([0-9A-Fa-f]+)", proc.stdout)
    return match.group(1).lower() if match else ""


def read_elf_machine(path: Path) -> str:
    proc = run_command(["readelf", "-h", str(path)], timeout=60, env=tool_env())
    if proc.returncode != 0:
        return ""
    match = re.search(r"^\s*Machine:\s*(.+?)\s*$", proc.stdout, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def elf_matches_architecture(path: Path, architecture: str) -> tuple[bool, str]:
    normalized = architecture.strip().lower()
    aliases = {
        "aarch64": "arm64",
        "x86": "amd64",
        "x86_64": "amd64",
        "x64": "amd64",
    }
    normalized = aliases.get(normalized, normalized)
    expected = {
        "arm64": {"aarch64"},
        "amd64": {"advanced micro devices x86-64", "x86-64"},
        "i386": {"intel 80386"},
        "armhf": {"arm"},
        "armel": {"arm"},
        "ppc64el": {"powerpc64"},
        "riscv64": {"risc-v"},
        "s390x": {"ibm s/390"},
    }.get(normalized)
    if not expected or normalized == "all":
        return True, read_elf_machine(path)
    machine = read_elf_machine(path)
    return machine.strip().lower() in expected, machine


def locate_runtime_elves(root: Path, rules: ElfRules) -> list[Path]:
    patterns = list(rules.so_globs) + list(rules.executable_globs)
    candidates: list[Path] = []
    if patterns:
        for pattern in patterns:
            candidates.extend(root.glob(pattern.lstrip("/")))
    else:
        for prefix in ("usr/bin", "usr/sbin", "bin", "sbin", "usr/lib", "lib"):
            base = root / prefix
            if base.exists():
                candidates.extend(path for path in base.rglob("*") if path.is_file())
    out: list[Path] = []
    seen: set[Path] = set()
    for path in sorted(candidates, key=elf_candidate_key):
        if not path.is_file() or path in seen:
            continue
        if path.is_symlink():
            resolved = path.resolve()
            try:
                if resolved.is_relative_to(root.resolve()):
                    path = resolved
            except AttributeError:  # pragma: no cover - Python < 3.9 compatibility.
                try:
                    resolved.relative_to(root.resolve())
                    path = resolved
                except ValueError:
                    pass
        if path in seen:
            continue
        rel = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, pattern) for pattern in rules.exclude_globs):
            continue
        if is_elf(path):
            seen.add(path)
            out.append(path)
    return out


def elf_candidate_key(path: Path) -> tuple[int, str]:
    return (1 if path.is_symlink() else 0, str(path))


def find_debug_file(debug_root: Path, build_id: str, runtime_relative_path: str = "") -> Path | None:
    if build_id:
        exact = debug_root / "usr" / "lib" / "debug" / ".build-id" / build_id[:2] / f"{build_id[2:]}.debug"
        if exact.exists() and is_elf(exact):
            return exact
    debug_base = debug_root / "usr" / "lib" / "debug"
    if not debug_base.exists():
        return None
    if runtime_relative_path:
        by_runtime_path = debug_base / runtime_relative_path
        if by_runtime_path.exists() and is_elf(by_runtime_path):
            if not build_id or read_build_id(by_runtime_path) == build_id:
                return by_runtime_path
    for path in sorted(debug_base.rglob("*")):
        if not path.is_file() or not is_elf(path):
            continue
        if not build_id or read_build_id(path) == build_id:
            return path
    return None


def unstrip_elf(runtime_elf: Path, debug_file: Path, output: Path) -> tuple[bool, str]:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and is_elf(output):
        return True, "reused existing unstripped ELF"
    proc = run_command(["eu-unstrip", "-o", str(output), str(runtime_elf), str(debug_file)], timeout=300)
    if proc.returncode != 0 or not output.exists():
        return False, (proc.stderr or proc.stdout).strip()
    return True, "eu-unstrip ok"


def nm_symbols(path: Path) -> dict[str, SymbolInfo]:
    return _nm_symbols_cached(str(path))


@lru_cache(maxsize=512)
def _nm_symbols_cached(path: str) -> dict[str, SymbolInfo]:
    proc = run_command(["nm", "-an", "--defined-only", path], timeout=120)
    if proc.returncode != 0:
        return {}
    symbols: dict[str, SymbolInfo] = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            address = int(parts[0], 16)
        except ValueError:
            continue
        kind = parts[1]
        name = parts[2]
        if kind.lower() not in {"t", "w"}:
            continue
        for alias in symbol_aliases(name):
            symbols.setdefault(alias, SymbolInfo(name=name, address=address, kind=kind))
    return symbols


def symbol_aliases(name: str) -> set[str]:
    aliases = {name}
    base = name.split("@", 1)[0]
    aliases.add(base)
    if base.startswith("."):
        aliases.add(base[1:])
    if "(" in base:
        aliases.add(base.split("(", 1)[0])
    for marker in (".isra.", ".constprop.", ".part.", ".cold", ".llvm.", ".lto_priv."):
        if marker in base:
            aliases.add(base.split(marker, 1)[0])
    return {item for item in aliases if item}


DIE_RE = re.compile(r"^\s*<(?P<level>\d+)><(?P<offset>[0-9A-Fa-f]+)>.*\(DW_TAG_(?P<tag>[A-Za-z0-9_]+)\)")
ATTR_RE = re.compile(r"\bDW_AT_(?P<attr>[A-Za-z0-9_]+)\s*[：:]\s*(?P<value>.*)$")
REF_RE = re.compile(r"<(?:0x)?(?P<offset>[0-9A-Fa-f]+)>")


def dwarf_records_for_functions(path: Path, functions: Iterable[str]) -> dict[str, tuple[DwarfRecord, ...]]:
    return _dwarf_records_for_functions_cached(str(path), tuple(sorted(set(functions))))


@lru_cache(maxsize=512)
def _dwarf_records_for_functions_cached(path: str, functions: tuple[str, ...]) -> dict[str, tuple[DwarfRecord, ...]]:
    if not functions:
        return {}
    aliases_by_function = {function: symbol_aliases(function) for function in functions}
    records_by_alias: dict[str, list[DwarfRecord]] = {}
    subprogram_aliases_by_offset: dict[str, set[str]] = {}
    subprogram_names_by_offset: dict[str, str] = {}

    for die in iter_dwarf_dies(path):
        tag = die["tag"]
        attrs = die["attrs"]
        if tag != "subprogram":
            continue
        names = dwarf_die_names(attrs)
        aliases = aliases_for_names(names)
        matched_aliases = target_aliases(aliases_by_function, aliases)
        if not matched_aliases:
            continue
        subprogram_aliases_by_offset[die["offset"]] = matched_aliases
        subprogram_names_by_offset[die["offset"]] = names[0] if names else ""
        kind = "dwarf_range_present" if dwarf_has_code_location(attrs) else "dwarf_abstract_only"
        record = DwarfRecord(
            name=names[0] if names else "",
            kind=kind,
            tag=tag,
            die_offset=format_dwarf_offset(die["offset"]),
            low_pc=attrs.get("low_pc", ""),
            high_pc=attrs.get("high_pc", ""),
            ranges=attrs.get("ranges", ""),
            entry_pc=attrs.get("entry_pc", ""),
        )
        add_dwarf_record(records_by_alias, matched_aliases, record)

    if not subprogram_aliases_by_offset:
        return {key: tuple(value) for key, value in records_by_alias.items()}

    for die in iter_dwarf_dies(path):
        if die["tag"] != "inlined_subroutine":
            continue
        attrs = die["attrs"]
        origin = dwarf_ref_offset(attrs.get("abstract_origin", ""))
        aliases = set(subprogram_aliases_by_offset.get(origin, set()))
        if not aliases:
            continue
        if not dwarf_has_code_location(attrs):
            continue
        names = dwarf_die_names(attrs)
        aliases.update(aliases_for_names(names))
        record = DwarfRecord(
            name=names[0] if names else subprogram_names_by_offset.get(origin, ""),
            kind="inline_only",
            tag=die["tag"],
            die_offset=format_dwarf_offset(die["offset"]),
            origin_offset=format_dwarf_offset(origin),
            low_pc=attrs.get("low_pc", ""),
            high_pc=attrs.get("high_pc", ""),
            ranges=attrs.get("ranges", ""),
            entry_pc=attrs.get("entry_pc", ""),
        )
        add_dwarf_record(records_by_alias, aliases, record)

    return {key: tuple(value) for key, value in records_by_alias.items()}


def iter_dwarf_dies(path: str, timeout: int = 300) -> Iterable[dict[str, Any]]:
    proc = subprocess.Popen(
        ["readelf", "--debug-dump=info", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    current: dict[str, Any] | None = None
    started = time.monotonic()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if time.monotonic() - started > timeout:
                proc.kill()
                break
            die_match = DIE_RE.match(line)
            if die_match:
                if current is not None:
                    yield current
                current = {
                    "level": int(die_match.group("level")),
                    "offset": normalize_dwarf_offset(die_match.group("offset")),
                    "tag": die_match.group("tag"),
                    "attrs": {},
                }
                continue
            if current is None:
                continue
            attr_match = ATTR_RE.search(line)
            if attr_match:
                current["attrs"][attr_match.group("attr")] = attr_match.group("value").strip()
        if current is not None:
            yield current
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def dwarf_die_names(attrs: dict[str, str]) -> list[str]:
    names: list[str] = []
    for attr in ("name", "linkage_name", "MIPS_linkage_name"):
        value = attrs.get(attr, "")
        if not value:
            continue
        text = dwarf_attr_text(value)
        if text and text not in names:
            names.append(text)
    return names


def dwarf_attr_text(value: str) -> str:
    text = value.strip()
    if ": " in text:
        text = text.rsplit(": ", 1)[1].strip()
    if text.startswith("(") and ")" in text:
        text = text.split(")", 1)[1].strip()
    return text


def aliases_for_names(names: Iterable[str]) -> set[str]:
    aliases: set[str] = set()
    for name in names:
        aliases.update(symbol_aliases(name))
    return aliases


def target_aliases(aliases_by_function: dict[str, set[str]], aliases: set[str]) -> set[str]:
    out: set[str] = set()
    for function, wanted_aliases in aliases_by_function.items():
        if aliases & wanted_aliases:
            out.add(function)
            out.update(aliases & wanted_aliases)
    return out


def add_dwarf_record(records_by_alias: dict[str, list[DwarfRecord]], aliases: set[str], record: DwarfRecord) -> None:
    for alias in aliases:
        records_by_alias.setdefault(alias, [])
        if record not in records_by_alias[alias]:
            records_by_alias[alias].append(record)


def dwarf_has_code_location(attrs: dict[str, str]) -> bool:
    return any(attrs.get(key) for key in ("low_pc", "ranges", "entry_pc"))


def dwarf_ref_offset(value: str) -> str:
    match = REF_RE.search(value)
    return normalize_dwarf_offset(match.group("offset")) if match else ""


def normalize_dwarf_offset(value: str) -> str:
    try:
        return f"{int(value, 16):x}"
    except ValueError:
        return value.lower().removeprefix("0x")


def format_dwarf_offset(value: str) -> str:
    normalized = normalize_dwarf_offset(value)
    return f"0x{normalized}" if normalized else ""


def disassembles(path: Path, symbol: SymbolInfo) -> bool:
    stop = symbol.address + 96
    disassembler = disassembler_for_elf(path)
    if not disassembler:
        return False
    proc = run_command(
        [
            disassembler,
            "-d",
            "--start-address",
            hex(symbol.address),
            "--stop-address",
            hex(stop),
            str(path),
        ],
        timeout=120,
        env=tool_env(),
    )
    if proc.returncode != 0:
        return False
    return bool(re.search(r"^\s*[0-9A-Fa-f]+:\s+[0-9A-Fa-f]{2}", proc.stdout, flags=re.MULTILINE))


def disassembler_for_elf(path: Path) -> str:
    machine = read_elf_machine(path).strip().lower()
    cross_prefixes = {
        "aarch64": "aarch64-linux-gnu-objdump",
        "arm": "arm-linux-gnueabihf-objdump",
        "powerpc64": "powerpc64le-linux-gnu-objdump",
        "risc-v": "riscv64-linux-gnu-objdump",
        "ibm s/390": "s390x-linux-gnu-objdump",
    }
    candidate = cross_prefixes.get(machine)
    if candidate:
        return candidate if shutil.which(candidate) else ""
    return "objdump" if shutil.which("objdump") else ""


def validate_functions(path: Path, functions: Iterable[str]) -> dict[str, object]:
    function_list = list(dict.fromkeys(functions))
    symbols = nm_symbols(path)
    symbol_checks: dict[str, tuple[SymbolInfo | None, bool]] = {}
    unresolved: list[str] = []
    for function in function_list:
        info = lookup_symbol(symbols, function)
        disassembly_ok = bool(info and disassembles(path, info))
        symbol_checks[function] = (info, disassembly_ok)
        if not disassembly_ok:
            unresolved.append(function)
    dwarf_records = dwarf_records_for_functions(path, unresolved) if unresolved else {}
    found: list[str] = []
    symbol_found: list[str] = []
    dwarf_found: list[str] = []
    inline_only: list[str] = []
    dwarf_range_present: list[str] = []
    dwarf_abstract_only: list[str] = []
    missing: list[str] = []
    no_disassembly: list[str] = []
    symbol_names: dict[str, str] = {}
    function_status: dict[str, dict[str, Any]] = {}
    for function in function_list:
        info, disassembly_ok = symbol_checks[function]
        symbol_disassembly_failed = False
        if info is not None and disassembly_ok:
            symbol_names[function] = info.name
            found.append(function)
            symbol_found.append(function)
            function_status[function] = {
                "status": "symbol_present",
                "evidence": "nm_defined_text_symbol",
                "symbol_name": info.name,
                "symbol_address": hex(info.address),
                "symbol_kind": info.kind,
            }
            continue

        if info is not None:
            symbol_names[function] = info.name
            symbol_disassembly_failed = True

        records = lookup_dwarf_records(dwarf_records, function)
        dwarf_status = classify_dwarf_records(records)
        if dwarf_status in {"dwarf_range_present", "inline_only"}:
            found.append(function)
            dwarf_found.append(function)
            if dwarf_status == "inline_only":
                inline_only.append(function)
            else:
                dwarf_range_present.append(function)
            function_status[function] = {
                "status": dwarf_status,
                "evidence": "elf_dwarf",
                "symbol_name": info.name if info else "",
                "symbol_disassembly": "failed" if info else "absent",
                "dwarf_records": [dwarf_record_json(item) for item in best_dwarf_records(records, dwarf_status)],
            }
        elif dwarf_status == "dwarf_abstract_only":
            dwarf_abstract_only.append(function)
            if symbol_disassembly_failed:
                no_disassembly.append(function)
                function_status[function] = {
                    "status": "symbol_no_disassembly",
                    "evidence": "nm_symbol_without_objdump_bytes_and_dwarf_no_code_range",
                    "symbol_name": info.name,
                    "symbol_disassembly": "failed",
                    "dwarf_records": [dwarf_record_json(item) for item in best_dwarf_records(records, dwarf_status)],
                }
            else:
                missing.append(function)
                function_status[function] = {
                    "status": "dwarf_abstract_only",
                    "evidence": "elf_dwarf_no_code_range",
                    "symbol_name": "",
                    "symbol_disassembly": "absent",
                    "dwarf_records": [dwarf_record_json(item) for item in best_dwarf_records(records, dwarf_status)],
                }
        elif symbol_disassembly_failed:
            no_disassembly.append(function)
            function_status[function] = {
                "status": "symbol_no_disassembly",
                "evidence": "nm_symbol_without_objdump_bytes",
                "symbol_name": info.name,
                "symbol_disassembly": "failed",
                "dwarf_records": [],
            }
        else:
            missing.append(function)
            function_status[function] = {
                "status": "missing",
                "evidence": "no_nm_symbol_or_dwarf_code_range",
                "symbol_name": info.name if info else "",
                "symbol_disassembly": "failed" if info else "absent",
                "dwarf_records": [],
            }
    ok = bool(function_list) and len(symbol_found) == len(function_list) and not no_disassembly
    available = bool(function_list) and not missing and set(found) == set(function_list)
    return {
        "ok": ok,
        "available": available,
        "availability": summarize_availability(function_status),
        "found": found,
        "symbol_found": symbol_found,
        "dwarf_found": dwarf_found,
        "inline_only": inline_only,
        "dwarf_range_present": dwarf_range_present,
        "dwarf_abstract_only": dwarf_abstract_only,
        "missing": missing,
        "no_disassembly": no_disassembly,
        "symbol_names": symbol_names,
        "function_status": function_status,
    }


def lookup_symbol(symbols: dict[str, SymbolInfo], function: str) -> SymbolInfo | None:
    for alias in (function, *sorted(symbol_aliases(function))):
        info = symbols.get(alias)
        if info is not None:
            return info
    return None


def lookup_dwarf_records(index: dict[str, tuple[DwarfRecord, ...]], function: str) -> list[DwarfRecord]:
    records: list[DwarfRecord] = []
    seen: set[tuple[str, str, str]] = set()
    for alias in (function, *sorted(symbol_aliases(function))):
        for record in index.get(alias, ()):
            key = (record.kind, record.tag, record.die_offset)
            if key in seen:
                continue
            seen.add(key)
            records.append(record)
    return records


def classify_dwarf_records(records: list[DwarfRecord]) -> str:
    kinds = {record.kind for record in records}
    if "dwarf_range_present" in kinds:
        return "dwarf_range_present"
    if "inline_only" in kinds:
        return "inline_only"
    if "dwarf_abstract_only" in kinds:
        return "dwarf_abstract_only"
    return "missing"

def best_dwarf_records(records: list[DwarfRecord], status: str) -> list[DwarfRecord]:
    if status == "missing":
        return []
    matching = [record for record in records if record.kind == status]
    if matching:
        return matching[:12]
    return records[:12]


def dwarf_record_json(record: DwarfRecord) -> dict[str, str]:
    return {
        "name": record.name,
        "kind": record.kind,
        "tag": record.tag,
        "die_offset": record.die_offset,
        "origin_offset": record.origin_offset,
        "low_pc": record.low_pc,
        "high_pc": record.high_pc,
        "ranges": record.ranges,
        "entry_pc": record.entry_pc,
    }


def summarize_availability(function_status: dict[str, dict[str, Any]]) -> str:
    statuses = {str(item.get("status") or "") for item in function_status.values()}
    if not statuses:
        return "no_functions"
    if statuses == {"symbol_present"}:
        return "symbol_present"
    available = {"symbol_present", "dwarf_range_present", "inline_only"}
    if statuses.issubset(available):
        if statuses.issubset({"symbol_present", "inline_only"}) and "inline_only" in statuses:
            return "inline_only"
        if statuses.issubset({"symbol_present", "dwarf_range_present"}) and "dwarf_range_present" in statuses:
            return "dwarf_range_present"
        return "dwarf_available"
    if "dwarf_abstract_only" in statuses:
        return "dwarf_abstract_only"
    return "missing"
