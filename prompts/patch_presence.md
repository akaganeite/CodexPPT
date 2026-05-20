You are doing an authorized local patch-presence evaluation.
Analyze exactly one CVE across the requested binaries.

Hard rules:
1. Do not use the network.
2. Do not use version-number matching as evidence.
3. Use only local binary evidence and the supplied metadata: symbols, strings, disassembly, DWARF line info, calls, branches, constants, and control-flow/guard differences.
4. Do not open, read, cat, sed, grep, or otherwise inspect source files referenced by DWARF/debug info paths, diff file paths, or absolute paths inside metadata. The metadata JSON included in this prompt is the only source-like context you may use.
5. You may use line/file annotations printed by binary tools such as objdump --line-numbers, because those annotations come from the binary's debug info. Do not follow those paths to read the actual source files.
6. If the resolved binary file does not exist under target_dir, return status not_found for that requested binary.
7. If evidence is not decisive, return inconclusive. Do not guess.
8. Final response must be valid JSON only, with no markdown fences.

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
- Start with one batched cross-binary scan for the key symbol/call/string pattern across all requested binaries. Then inspect at most one vulnerable-side representative and one patched-side representative in detail; classify sibling binaries by the same decisive local pattern.
- Keep the final JSON compact: at most 2 evidence strings per binary, each under 25 words; reasoning under 35 words. Include only decisive addresses/calls/patterns, not full command narratives.

Status semantics:
- present: patch is present in the binary.
- absent: patch is absent / vulnerable-side behavior is present.
- inconclusive: binary exists but evidence is insufficient.
- not_found: resolved binary file is missing.

Required JSON shape:
{
  "results": [
    {
      "cve": "CVE-ID",
      "binary": "requested-binary-name",
      "status": "present|absent|inconclusive|not_found",
      "confidence": "high|medium|low",
      "evidence": ["concise concrete evidence"],
      "reasoning": "brief logical explanation"
    }
  ]
}

Task payload JSON:
{{TASK_PAYLOAD_JSON}}
