You are doing an authorized local patch-presence evaluation.
Analyze exactly one CVE across the requested deployed binaries.

The target binaries were collected from distribution packages and may include
debuginfo merged from separate debug packages. They may have symbols and DWARF,
but this is not guaranteed for every function, build, or optimization level.
Base the decision primarily on root_cause_analysis, patch_intent_analysis,
behavior_changes, patch_hunk, reduced_function_code, and local binary evidence.

Decision focus:
- First extract the vulnerable mechanism from root_cause_analysis.
- Then extract the intended security property and concrete behavior changes from patch_intent_analysis.
- Treat behavior_changes as the primary patch-presence checklist. A binary is present only when local binary evidence shows the patched behavior, not merely the absence of an obvious vulnerable call.
- A binary is absent only when local binary evidence shows vulnerable-side behavior.
- Before choosing present/absent, check whether the vulnerable mechanism or patch hunk depends on architecture, word size, OS/backend, optional dependency, protocol, or feature configuration.
- Return not_affected when local binary evidence shows that such a required condition is not present or not applicable in this binary. This is a build/configuration applicability decision, not a patch-presence claim.
- not_affected requires positive local evidence of inapplicability, such as an ELF class/word size that rules out a guarded 32-bit-only bug, missing optional vulnerable dependency/backend support, or relevant code/features not compiled into the binary.
- Use patch_hunk and reduced_function_code as compact source-like hints for what binary behavior should change. Do not infer status from version numbers or source paths.

Hard rules:
1. Do not use the network.
2. Do not use version-number matching as evidence.
3. Use only local binary evidence and the supplied metadata: symbols, strings, disassembly, DWARF line info, calls, branches, constants, data flow, and control-flow/guard differences.
4. Do not open, read, cat, sed, grep, or otherwise inspect source files referenced by DWARF/debug info paths, diff file paths, or absolute paths inside metadata. The metadata JSON included in this prompt is the only source-like context you may use.
5. You may use line/file annotations printed by binary tools such as objdump --line-numbers, because those annotations come from the binary's debug info. Do not follow those paths to read the actual source files.
6. Do not inspect files outside target_dir, except the supplied safe_objdump helper path. Do not scan parent directories or sibling directories for alternate binaries.
7. If the resolved binary file does not exist under target_dir, return status not_found for that requested binary.
8. If evidence is not decisive for present, absent, or not_affected, return inconclusive. Do not guess.
9. Final response must be valid JSON only, with no markdown fences.

Tool guidance for deployed binaries:
- Start with file existence, `file`, `nm`, `readelf`, and narrowly filtered `strings` or relocation/import checks.
- Prefer symbol/DWARF evidence when it is available. Use `nm`, `readelf -Ws`, and bounded disassembly around the relevant function or call site before broader search.
- If `nm` or symbol-table lookup does not find the metadata target function, do not treat that alone as proof that the code is absent or not affected. The function may be inlined, optimized away, renamed, hidden, local-only, split into cold/hot parts, or missing from the available symbol table.
- When the target symbol cannot be located, fall back to stripped-binary reasoning: locate the relevant behavior through strings, imported calls, constants, byte patterns, nearby diagnostics, DWARF line annotations if present, and cross-binary control-flow differences.
- You may use `objdump`, `readelf`, `nm`, `strings`, `xxd`, `dd`, `rg`, `perl`, `python3`, or the repository helper `python3 {{SAFE_OBJDUMP_HELPER}} --binary PATH ...`.
- For disassembly, the helper supports `--symbol SYMBOL`, `--addr 0xADDR`, `--window BYTES`, `--grep REGEX`, `--context N`, `--demangle`, and `--line-numbers`.
- There is no fixed disassembly-call budget, window limit, or objdump output-size limit for this deployed-binary prompt. Keep commands purposeful, prefer filtered output, and stop inspecting a binary once evidence is decisive.
- Reuse evidence across binaries when the same symbol, string, call pattern, or address-family pattern applies. Do not repeat broad scans for every sibling binary unless the evidence does not transfer.
- If a function is not compiled in or the relevant feature/backend is disabled, collect positive local evidence for that before returning not_affected.

Status semantics:
- present: patch is present in the binary.
- absent: patch is absent / vulnerable-side behavior is present.
- not_affected: binary exists, but local architecture/build/configuration evidence shows the vulnerable mechanism is not applicable.
- inconclusive: binary exists but evidence is insufficient.
- not_found: resolved binary file is missing.

Required JSON shape:
{
  "results": [
    {
      "cve": "CVE-ID",
      "binary": "requested-binary-name",
      "status": "present|absent|not_affected|inconclusive|not_found",
      "confidence": "high|medium|low",
      "evidence": ["concise concrete evidence"],
      "reasoning": "brief logical explanation"
    }
  ]
}

Task payload JSON:
{{TASK_PAYLOAD_JSON}}
