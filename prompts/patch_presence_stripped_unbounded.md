You are doing an authorized local patch-presence evaluation.
Analyze exactly one CVE across the requested binaries.

The target binaries may be stripped: symbol tables and DWARF debug info may be
absent. Base the patch-presence decision primarily on root_cause_analysis,
patch_intent_analysis, behavior_changes, patch_hunk, reduced_function_code, and
local binary evidence.

Decision focus:
- First extract the vulnerable mechanism from root_cause_analysis.
- Then extract the intended security property and concrete behavior changes from patch_intent_analysis.
- Treat behavior_changes as the primary patch-presence checklist.
- Before choosing present/absent, check whether the vulnerable mechanism or patch
  hunk is conditioned on architecture, word size, OS/backend, optional
  dependency, protocol, or feature configuration.
- Return not_affected when local binary evidence shows that such a required
  condition is not present or not applicable in this binary. This is a
  build/configuration applicability decision, not a patch-presence claim.
- A binary is present only when local binary evidence shows the patched behavior.
- A binary is absent only when local binary evidence shows the vulnerable-side behavior.
- not_affected requires positive local evidence of inapplicability, such as an
  ELF class/word size that rules out a guarded 32-bit-only bug, missing optional
  vulnerable dependency/backend support, or relevant code/features not compiled
  into the binary.
- Use patch_hunk and reduced_function_code as compact semantic anchors for expected binary behavior. Do not infer status from version numbers or source paths.

Hard rules:
1. Do not use the network.
2. Do not use version-number matching as evidence.
3. Use only local binary evidence and the supplied metadata: strings, dynamic symbols, imported calls, raw/disassembled instructions, constants, branches, data flow, and control-flow/guard differences.
4. Do not open, read, cat, sed, grep, or otherwise inspect source files referenced by DWARF/debug info paths, diff file paths, or absolute paths inside metadata. The metadata JSON included in this prompt is the only source-like context you may use.
5. Do not inspect files outside target_dir, except the supplied safe_objdump helper path. Do not scan parent directories or sibling directories for alternate binaries.
6. If the resolved binary file does not exist under target_dir, return status not_found for that requested binary.
7. If evidence is not decisive for present, absent, or not_affected, return inconclusive. Do not guess.
8. Final response must be valid JSON only, with no markdown fences.

Tool guidance for stripped binaries:
- Start with file existence, `file`, `readelf`, `strings`, dynamic symbol/import tables, and byte-pattern searches.
- You may use `objdump`, `readelf`, `xxd`, `dd`, `rg`, `perl`, `python3`, or the repository helper `python3 {{SAFE_OBJDUMP_HELPER}} --binary PATH ...`.
- There is no fixed disassembly-call budget, window limit, or objdump output-size limit in this experiment. Still keep commands purposeful and stop once evidence is decisive.
- Without symbols, locate relevant code by imported calls such as `sprintf`, `strlen`, `printf`, nearby format strings, constants, relative call targets, and cross-binary byte/control-flow differences.
- For CVE-2021-20294-like evidence, distinguish the vulnerable behavior `sprintf(buffer, "@%s", version_string)` from the patched behavior `strlen(version_string) + 1` used for length calculation while retaining bounded integer formatting for `" (%d)"`.

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
