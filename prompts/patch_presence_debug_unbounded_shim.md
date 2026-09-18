You are doing an authorized local patch-presence evaluation.
Analyze exactly one CVE for exactly one requested binary.

This shim prompt is used with reduced metadata. Base the patch-presence decision
primarily on vulnerability_description, patch_commit_message, patch_hunk,
functions, and local binary evidence. Target binaries may expose symbols and
DWARF debug information; use these only as evidence embedded in the binary.

Decision focus:
- First infer the vulnerable mechanism from vulnerability_description,
  patch_commit_message, and patch_hunk.old_lines.
- Then infer the intended patched behavior from patch_hunk.new_lines and the
  surrounding patch_commit_message.
- Treat patch_hunk.old_lines and patch_hunk.new_lines as the primary
  patch-presence checklist.
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
- Use functions and patch_hunk as compact source-like hints for expected binary
  behavior. Do not infer status from version numbers or source paths.

Hard rules:
1. Do not use the network.
2. Do not use version-number matching as evidence.
3. Use only local binary evidence and the supplied metadata: symbols, strings,
   disassembly, DWARF line info, calls, branches, constants, data flow, and
   control-flow/guard differences.
4. Do not open, read, cat, sed, grep, or otherwise inspect source files
   referenced by DWARF/debug info paths, diff file paths, or absolute paths
   inside metadata. The metadata JSON included in this prompt is the only
   source-like context you may use.
5. You may use line/file annotations printed by binary tools such as
   objdump --line-numbers, because those annotations come from the binary's
   debug information. Do not follow those paths to read actual source files.
6. Do not inspect files outside target_dir, except the supplied safe_objdump
   helper path. Do not scan parent directories or sibling directories for
   alternate binaries.
7. If the resolved binary file does not exist under target_dir, return status
   not_found for that requested binary.
8. If evidence is not decisive for present, absent, or not_affected, return
   inconclusive. Do not guess.
9. Final response must be valid JSON only, with no markdown fences.

Tool guidance:
- Start with file existence, `file`, `nm`, `readelf`, `strings`, dynamic
  symbol/import tables, and line/symbol searches to locate evidence.
- You may use `objdump`, `readelf`, `nm`, `addr2line`, `xxd`, `dd`,
  `rg`, `perl`, `python3`, or the repository helper
  `python3 {{SAFE_OBJDUMP_HELPER}} --binary PATH ...`.
- There is no fixed tool-call, disassembly-call, window, or output-size budget
  in this experiment. Keep commands purposeful and stop once evidence is
  decisive.
- Use symbols and DWARF to locate relevant code, then verify the required
  branch, call-site, data flow, or guard in local disassembly. A matching line
  annotation alone is not decisive unless it establishes the changed behavior.

Status semantics:
- present: patch is present in the binary.
- absent: patch is absent / vulnerable-side behavior is present.
- not_affected: binary exists, but local architecture/build/configuration
  evidence shows the vulnerable mechanism is not applicable.
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
