You are doing an authorized local patch-presence evaluation.
Analyze exactly one CVE across the requested binaries.

The supplied metadata may not include full source code. Base the
patch-presence decision primarily on root_cause_analysis,
patch_intent_analysis, behavior_changes, patch_hunk, and local binary
evidence. If reduced_function_code is present, use it only as a compact
semantic anchor for the relevant behavior and control-flow point.

Decision focus:
- First extract the vulnerable mechanism from root_cause_analysis.
- Then extract the intended security property and concrete behavior changes from patch_intent_analysis.
- Treat the behavior changes as the primary patch-presence checklist. A binary is present only when local binary evidence shows the patched behavior, not merely the absence of an obvious vulnerable call.
- Compare local binary evidence against the specific behavior_changes in metadata. Do not use the mere presence or absence of a single symbol, call, string, or constant as decisive evidence unless metadata says that item alone is the patch behavior. Prefer evidence that places the changed operation in the relevant function, branch, guard, data-flow, or call-site context.
- Before choosing present/absent, check whether the vulnerable mechanism or patch hunk is conditioned on architecture, word size, OS/backend, optional dependency, protocol, or feature configuration.
- Return not_affected when local binary evidence shows that such a required condition is not present or not applicable in this binary. This is a build/configuration applicability decision, not a patch-presence claim, and requires positive local evidence of inapplicability (e.g. an ELF class/word size that rules out a guarded 32-bit-only bug, a missing optional vulnerable dependency/backend, or relevant features not compiled in) rather than the mere absence of the target symbol.
- Use patch_hunk and reduced_function_code only as compact source-like hints for what binary behavior should change. Do not infer status from version numbers or source paths.

Hard rules:
1. Do not use the network.
2. Do not use version-number matching as evidence.
3. Use only local binary evidence and the supplied metadata: symbols, strings, disassembly, DWARF line info, calls, branches, constants, and control-flow/guard differences.
4. Do not open, read, cat, sed, grep, or otherwise inspect source files referenced by DWARF/debug info paths, diff file paths, or absolute paths inside metadata. The metadata JSON included in this prompt is the only source-like context you may use.
5. You may use line/file annotations printed by binary tools such as objdump --line-numbers, because those annotations come from the binary's debug info. Do not follow those paths to read the actual source files.
6. Do not inspect files outside target_dir, except the supplied safe_objdump helper path. Do not scan parent directories or sibling directories for alternate binaries.
7. If the resolved binary file does not exist under target_dir, return status not_found for that requested binary.
8. If evidence is not decisive for present, absent, or not_affected, return inconclusive. Do not guess.
9. Final response must be valid JSON only, with no markdown fences.

Tool-output budget rules:
- Prefer `nm`, `strings`, `readelf`, and narrowly filtered commands to locate evidence before disassembly.
- For disassembly, use the bounded helper from the repository utils directory: `python3 {{SAFE_OBJDUMP_HELPER}} --binary PATH ...`.
- `{{SAFE_OBJDUMP_HELPER}}` supports `--symbol SYMBOL`, `--addr 0xADDR`, `--window BYTES`, `--grep REGEX`, `--context N`, `--demangle`, and `--line-numbers`. Default output is capped at 8 KiB; keep caps unless a small increase is essential.
- Start with `--grep` plus small `--context` values. Use `--window` only after you know the relevant function or address; normally keep `--window` at or below 1024 bytes and `--context` at or below 4.
- Do not run naked `objdump` over an entire section, entire large function, or broad address range. Any raw objdump output must be limited to at most 120 lines or 8 KiB. If more is needed, narrow the address range or grep pattern instead.
- Disassembly call budget: at most 2 `{{SAFE_OBJDUMP_HELPER}}` calls per requested binary, and at most 10 total disassembly calls for the CVE. Count raw `objdump` as a disassembly call too.
- If you cannot reach decisive evidence inside that budget, return inconclusive for the affected binary instead of continuing exploration.
- Reuse evidence across binaries when the same symbol and pattern are being checked; do not repeat broad scans for every binary.
- Avoid repeated exploration: once you have decisive local evidence for a binary, stop inspecting that binary.
- Start with one batched cross-binary scan for the key symbol/call/string pattern across all requested binaries. After finding the decisive pattern in one patched-side representative and one vulnerable-side representative, classify sibling binaries using the same narrow symbol/call/string pattern. Do not repeat full-window disassembly for every sibling unless the representative evidence does not transfer.
- Keep the final JSON compact: at most 2 evidence strings per binary, each under 25 words; reasoning under 35 words. Include only decisive addresses/calls/patterns, not full command narratives.

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
