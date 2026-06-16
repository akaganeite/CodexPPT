# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo does

This is a research harness for **binary patch-presence testing**: given a CVE and a set of
target binaries, decide whether each binary contains the *patched* behavior (`present`), the
*vulnerable* behavior (`absent`), is `not_affected` (the bug is inapplicable to this build), or
is `inconclusive`. The detection itself is delegated to an LLM agent driven via `codex exec`
(OpenAI Codex, or a local DeepSeek-compatible proxy). This wrapper builds prompts, runs one
agent per task, parses/validates the JSON answer, and scores it against groundtruth.

The agent is deliberately constrained to *local binary evidence only* — no network, no
version-number matching, no reading source files. See `prompts/` for the exact contract.

## Running a batch

The entrypoint is `codex_patch_presence_batch.py` (a thin shim over the `codex_batch/`
package). `readme.md` has copy-pasteable example invocations (openai + dpsk). A minimal run:

```bash
python3 codex_patch_presence_batch.py \
  --project-json   metadata/curl/curl_project_source_analysis.behavior.json \
  --testset-json   datasets/curl_dataset4ppt_20/testset.json \
  --groundtruth-json datasets/curl_dataset4ppt_20/groundtruth.json \
  --target-dir     /path/to/binaries \
  --opt o0 \
  --output         runs/<name>_results.json \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --binarywise
```

Key flags (full list in `codex_batch/cli.py`):
- `--project <name>` derives `--project-json`, `--testset-json`, `--target-dir`, `--output`
  from conventional locations (see `paths.py::derive_project_paths`) instead of passing each.
- `--binarywise` runs one `codex exec` per **(CVE, binary)** pair instead of one per CVE.
  Most current experiments use this for isolation and parallelizable retries.
- `--provider openai|dpsk`. `dpsk` rewrites Codex config to route through a local proxy
  (`--dpsk-base-url`, `--dpsk-model`); see `providers.py`.
- `--jobs N` runs N tasks concurrently (default 1 = serial; lowering it is the 429 throttle).
  Output content is deterministic regardless of `--jobs`; only the on-disk write order varies.
- `--resume` skips tasks already in `--output`; add `--retry-errors` to re-run only
  `status=error` rows.
- `--dry-run` writes prompts to `--raw-dir` without calling the model — use this to inspect
  exactly what the agent sees.
- `--no-anonymize-targets` disables target anonymization (see below).
- `--reasoning-effort`, `--timeout`, `--sandbox`, `--codex-json-events` tune the codex run.

There is no test suite, linter, or build step. The modules are plain Python 3.10+ stdlib
(no third-party deps for the runner). Iterate with `--dry-run` and small `--limit`/`--cve`.

## Architecture: the `codex_batch/` package

`orchestrator.py` is the spine — read it first. `run_batch()` resolves paths, validates
inputs, loads metadata + testset, selects CVEs, filters out already-done tasks (`should_skip`),
then runs `process_cve()` per task through a `ThreadPoolExecutor` (`--jobs`, default 1 = serial).
A single lock guards every `merged` mutation + `write_json`; everything else (codex exec,
parsing, remap) stays off the lock so concurrent tasks truly overlap.
`process_cve()` is the per-task pipeline; each stage is a single-purpose module:

1. **`run_state.py`** — resume/skip logic, CVE selection, `safe_run_id` slugging.
2. **`anonymize.py`** — *critical for evaluation integrity*. Before the agent runs, target
   binaries are copied into a temp dir under neutral names (`target_001`, …) and the agent's
   working dir (`cd`) is set there. This prevents the agent from inferring the answer from
   filenames/version strings. After the run, `remap_result_to_original()` maps answers and
   evidence text back to the real binary names. On by default; `--no-anonymize-targets` off.
3. **`prompt.py`** — fills the `{{TASK_PAYLOAD_JSON}}` and `{{SAFE_OBJDUMP_HELPER}}`
   placeholders in a `prompts/*.md` template with the CVE metadata + binary list.
4. **`runner.py`** — builds and spawns the `codex exec` subprocess, streams stdout/stderr,
   captures the final answer from `--output-last-message`, and writes per-task timing
   (`*.timing.json/.md`, parsed from `--json` event stream).
5. **`schema.py`** — the JSON `--output-schema` the agent must satisfy.
6. **`results.py`** — `extract_json_object()` (tolerant JSON parsing) + `validate_cve_result()`
   (coerces the agent's output into the canonical per-binary `{status, confidence, evidence,
   reasoning}` shape; fills `error` rows for missing binaries).
7. **`evaluation.py`** — scores merged results vs. groundtruth → metrics JSON. Read the
   module docstrings: `not_found` is excluded from totals; `not_affected` is scored
   separately; `inconclusive`/`error` count toward TC (Detection Success Rate denominator)
   but not Accuracy. `expected_status_for_binary()` matches groundtruth by full binary name
   first, then falls back to a parsed upstream version.

Cross-cutting: `io.py` (atomic `write_json`, `is_relative_to`), `paths.py`
(`resolve_requested_binary` — maps a requested testcase name like `curl-7.58.0-curl` to the
on-disk optimized file `curl-7.58.0-o0-curl`), `testset.py` (input normalization).

### Important data-format constraints
- `testset.json` and `groundtruth.json` **only** accept the *dataset export list* format
  (`[{"CVE": ..., "vuln": [...], "patch": [...], "not_affected": [...]}]` or with
  `"binaries"`). The legacy `CVE -> [binaries]` top-level-object format is intentionally
  rejected (`testset.py`, `evaluation.py::normalize_groundtruth`). The legacy files still
  present under `testset/` and `groundtruth/` are kept for historical reference and will
  **not** load with the current code — new datasets go under `datasets/<name>/`.
- Groundtruth must live **outside** the agent-visible `--target-dir` and `--cd`;
  `validate_inputs()` hard-errors otherwise, so the agent can never see the answer key.

## `utils/safe_objdump.py` — the agent's bounded disassembler

The agent is told to prefer this helper over raw `objdump`. It exposes bounded windows of
disassembly (by `--symbol`, `--addr`, or `--grep` with context) with output-byte caps, so the
model gets evidence without flooding its context. Limits are read from `utils/config.json`
(`safe_objdump` section). When anonymizing, this helper + config are copied into the temp
working dir alongside the targets. Note the "unbounded" prompt variant relaxes the *guidance*
but the helper itself always enforces config caps.

## `metadata/` — offline metadata generation pipeline

Separate, run-ahead-of-time pipeline that produces the `--project-json` consumed above. It is
*not* part of the detection runtime. `run_metadata_pipeline.py` chains three steps:
1. `build_initial_project_json.py` — extract CVE/function list + diff paths from a CVE-Dataset
   export (paths under `/home/zhangxb/patch/related-works/CVE-Dataset/`).
2. `project_source_analysis.py` — AST/diff analysis → patch hunks, reduced function code,
   def/use traces. Emits `.full.json` and a compact `.min.json`.
3. `generate_behavior_analysis_deepseek.py` — calls DeepSeek to add `root_cause_analysis` and
   `patch_intent_analysis`, producing the `.behavior.json` the detection prompt relies on.

The `.behavior.json` is the richest project metadata and the one to pass as `--project-json`.
See `metadata/<project>/*_metadata_pipeline.md` for a recorded run with exact commands.

## Layout quick reference
- `runs/` — experiment outputs (results JSON, `.metrics.json`, raw per-task dirs). Gitignored.
- `analysis/` — written-up comparisons and per-CVE deep dives (Markdown + JSON).
- `prompts/` — agent contracts: `patch_presence.md` (base), `_deployed.md` (distro packages),
  `_stripped_unbounded.md` (stripped binaries, no debug info — the current default).
- `datasets/<name>/` — current testset + groundtruth pairs (export-list format).
