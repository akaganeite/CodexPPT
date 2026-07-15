# CLAUDE.md

This file gives implementation-level guidance to Claude Code when working in this
repository. For the run/handoff playbook (how to launch an experiment on a new
machine, dataset checks, troubleshooting, metrics interpretation), see
**`AGENTS.md`**; for a short user-facing intro and example invocations, see
**`readme.md`**. The three intentionally overlap; keep them consistent when you
change runtime behavior.

## What this repo does

This is a research harness for **binary patch-presence testing**: given a CVE and a
set of target binaries, decide for each binary whether it contains the *patched*
behavior (`present`), the *vulnerable* behavior (`absent`), is `not_affected`
(the bug is inapplicable to this build), is `inconclusive` (evidence not
decisive), was `not_found` (the target binary could not be resolved), or
`error` (the `codex exec` run itself failed). The detection is delegated to an
LLM agent driven via `codex exec`; this wrapper builds prompts, runs one agent
per task, anonymizes targets, parses/validates the JSON answer, and scores it
against groundtruth.

The agent is deliberately constrained to *local binary evidence only* - no network,
no version-number matching, no reading source files. See `prompts/` for the exact
contract and `AGENTS.md` "Safety and Data Leakage Rules" for the invariants.

## Running a batch

The entrypoint is `codex_patch_presence_batch.py` (a thin shim over the
`codex_batch/` package). A canonical dataset4ppt run (stripped binaries,
binarywise, the current default profile):

```bash
python3 codex_patch_presence_batch.py \
  --project-json   /home/zhangxb/extdisk/dataset4ppt/curl/exports/curl_behavior.json \
  --testset-json   /home/zhangxb/extdisk/dataset4ppt/curl/exports/testset.json \
  --groundtruth-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/groundtruth_with_not_affected.json \
  --target-dir     /home/zhangxb/extdisk/dataset4ppt/curl/binaries/target/curl_stripped \
  --compiler gcc --opt O2 \
  --output         runs/curl_o2_stripped_results.json \
  --raw-dir        runs/curl_o2_stripped_raw \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --binarywise --model-profile codex_default --codex-json-events --jobs 4 --timeout 3600
```

Dataset layout, file resolution, and the required `jq` format checks are
documented in `AGENTS.md` ("Dataset Layout", "Dataset Format Checks"). In short:
the dataset root is `/home/zhangxb/extdisk/dataset4ppt/<project>/`; the four
inputs resolve to `exports/<project>_behavior.json`, `exports/testset.json`,
`exports/groundtruth_with_not_affected.json`, and
`binaries/target/<project>_stripped`.

Key flags (full list in `codex_batch/cli.py`):
- `--project <name>` derives `--project-json`, `--testset-json`, `--target-dir`,
  `--output` from conventional locations (`paths.py::derive_project_paths`) instead
  of passing each. Most dataset4ppt runs pass the paths explicitly as above.
- `--binarywise` runs one `codex exec` per **(CVE, binary)** pair instead of one
  per CVE. Current experiments use this for isolation and parallelizable retries.
- `model_config.json` is the fixed model/provider configuration source (see below).
  Use `--model-profile <name>` to select a profile, or omit it to use
  `active_profile`. `--provider` is a legacy alias only (`providers.py`).
- `--jobs N` runs N tasks concurrently (default 1 = serial; lowering it is the 429
  throttle). Output content is deterministic regardless of `--jobs`; only the
  on-disk write order varies.
- `--resume` skips tasks already in `--output`; add `--retry-errors` to re-run only
  `status=error` rows.
- `--dry-run` writes prompts to `--raw-dir` without calling the model - use this to
  inspect exactly what the agent sees.
- `--no-anonymize-targets` disables target anonymization (see below).
- `--reasoning-effort`, `--timeout`, `--sandbox`, `--codex-json-events` tune the codex run.

### Pre-run smoke test (mandatory before a full run)

Before any full experiment, follow `AGENTS.md` "Pre-run smoke test workflow":
1. **Single case**: `--limit 1 --jobs 1` on one CVE - confirm a valid status (not
   `error`) and that timing/output files are written.
2. **Six concurrent**: `--limit 6 --jobs 6` - confirm six `codex exec` tasks run in
   parallel with no conflicts/backend failures.
3. Only then propose the full run. Diagnose any failure via
   `AGENTS.md` "Quick Troubleshooting" before retrying.

There is no test suite, linter, or build step. The modules are plain Python 3.10+
stdlib (no third-party deps for the runner). Iterate with `--dry-run` and small
`--limit`/`--cve`.

## Model configuration

All model/provider config lives in `model_config.json` at the repo root; the path
is fixed and there is no CLI flag for a different file (`providers.py::
MODEL_CONFIG_PATH`). `active_profile` is currently `cliproxy_gpt55_medium`.

Profiles (`--model-profile <name>`):
- `codex_default` - inherits the current Codex CLI config (`provider: codex`).
- `dpsk_flash` - DeepSeek-compatible local endpoint, `deepseek-v4-flash`, reasoning off.
- `pptagent_glm52` - PPTAgent endpoint, `glm-5.2`.
- `cliproxy_gpt55_medium` - local CLIProxyAPI, `gpt-5.5`, reasoning on/medium (active).
- `volc_glm52` - Volcengine Ark agent-plan endpoint, `glm-5.2`.

`--reasoning-effort` overrides the profile's reasoning effort. `--provider` maps a
short alias (`openai`/`dpsk`/`pptagent`/`cliproxy`/`volc`) to a profile but is
deprecated; use `--model-profile`. Profile field reference: see `AGENTS.md`
"Model Configuration" and `providers.py::parse_profile`.

## Architecture: the `codex_batch/` package

`orchestrator.py` is the spine - read it first. `run_batch()` resolves paths,
validates inputs, loads metadata + testset, selects CVEs, filters out already-done
tasks (`should_skip`), then runs `process_cve()` per task through a
`ThreadPoolExecutor` (`--jobs`, default 1 = serial). A single lock guards every
`merged` mutation + `write_json`; everything else (codex exec, parsing, remap)
stays off the lock so concurrent tasks truly overlap.
`process_cve()` is the per-task pipeline; each stage is a single-purpose module:

1. **`run_state.py`** - resume/skip logic (`should_skip`, pre-submission pure read),
   CVE selection, `safe_run_id` slugging.
2. **`anonymize.py`** - *critical for evaluation integrity*. Before the agent runs,
   target binaries are copied into a temp dir under neutral names (`target_001`, …)
   and the agent's working dir (`cd`) is set there. This prevents the agent from
   inferring the answer from filenames/version strings. After the run,
   `remap_result_to_original()` maps answers and evidence text back to the real
   binary names. On by default; `--no-anonymize-targets` off. The anonymous->original
   map is written to `<run_id>.anonymized_targets.json`.
3. **`prompt.py`** - fills the `{{TASK_PAYLOAD_JSON}}` and `{{SAFE_OBJDUMP_HELPER}}`
   placeholders in a `prompts/*.md` template with the CVE metadata + binary list.
4. **`runner.py`** - builds and spawns the `codex exec` subprocess, streams
   stdout/stderr, captures the final answer from `--output-last-message`, and writes
   per-task timing (`*.timing.json/.md`, parsed from the `--json` event stream).
   `run_codex` takes `cd`/`target_dir`/`safe_objdump_dir` explicitly so the caller
   can vary them per task (anonymized temp dirs) without mutating shared `args`.
5. **`schema.py`** - the JSON `--output-schema` the agent must satisfy.
6. **`results.py`** - `extract_json_object()` (tolerant JSON parsing) +
   `validate_cve_result()` (coerces the agent's output into the canonical per-binary
   `{status, confidence, evidence, reasoning}` shape; fills `error` rows for missing
   binaries). Has a 3-shape fallback because some proxies (e.g. dpsk) may not honor
   `--output-schema`.
7. **`evaluation.py`** - scores merged results vs. groundtruth -> metrics JSON. Read
   the module docstrings: `not_found` is excluded from totals; `not_affected` is
   scored separately; `inconclusive`/`error` count toward TC (Detection Success Rate
   denominator) but not Accuracy. `expected_status_for_binary()` matches groundtruth
   by full binary name first, then falls back to a parsed upstream version.

Cross-cutting: `io.py` (atomic `write_json`, `is_relative_to`), `paths.py`
(`resolve_requested_binary` - maps a requested testcase name like
`openssl-1.0.1j-openssl` to the on-disk `<name>-<compiler>-<opt>` file, with a
`-deployed` variant for distro packages), `testset.py` (input normalization).

### Important data-format constraints
- `testset.json` and `groundtruth.json` **only** accept the *dataset export list*
  format (`[{"CVE": …, "binaries": [...]}]` or
  `{"CVE": …, "vuln": [...], "patch": [...], "not_affected": [...]}`). The legacy
  `CVE -> [binaries]` top-level-object format is intentionally rejected
  (`testset.py`, `evaluation.py::normalize_groundtruth`). Old files under `testset/`
  and `groundtruth/` (and the now-empty `datasets/`) are historical and will **not**
  load - current datasets live under
  `/home/zhangxb/extdisk/dataset4ppt/<project>/exports/`.
- Groundtruth must live **outside** the agent-visible `--target-dir` and `--cd`;
  `validate_inputs()` hard-errors otherwise, so the agent can never see the answer key.

## `utils/safe_objdump.py` - the agent's bounded disassembler

The agent is told to prefer this helper over raw `objdump`. It exposes bounded windows
of disassembly (by `--symbol`, `--addr`, or `--grep` with context) with output-byte
caps, so the model gets evidence without flooding its context. Limits are read from
`utils/config.json` (`safe_objdump` section). When anonymizing, this helper + config
are copied into the temp working dir alongside the targets. Note the "unbounded"
prompt variant relaxes the *guidance* but the helper itself always enforces config caps.

## `metadata/` - offline metadata generation (deprecated for generation, products still consumed)

The detection prompt consumes behavior metadata (`root_cause_analysis`,
`patch_intent_analysis`, behavior changes). Two sources exist on disk:

- **Dataset export** (preferred for runs): `<dataset>/exports/<project>_behavior.json`.
- **Repo-local generated copy**: `metadata/<project>/*_project_source_analysis.behavior.json`.

The `metadata/` scripts that *generate* this JSON are a separate, run-ahead-of-time
pipeline and are **no longer maintained** - do not regenerate metadata for normal
runs; use the exported `<project>_behavior.json` already in the dataset. The scripts
are kept because their `.behavior.json` products are still valid runtime inputs and
the directory must not be deleted. For reference, the pipeline was:
`run_metadata_pipeline.py` chaining `build_initial_project_json.py` (CVE/function
extraction from a CVE-Dataset export) -> `project_source_analysis.py` (AST/diff
analysis -> `.full.json`/`.min.json`) -> `generate_behavior_analysis_deepseek.py`
(adds root-cause/patch-intent -> `.behavior.json`). See
`metadata/<project>/*_metadata_pipeline.md` for a recorded run.

## Outputs

Each run writes (see `AGENTS.md` "Output Layout" for the full file list and JSON
shapes):

- `--output`: merged JSON keyed by CVE -> binary -> `{status, confidence, reasoning, evidence}`.
- `--metrics-output` (defaults to `<output>.metrics.json`): metrics JSON with
  `metrics` (`A`/`P`/`R`/`F1`/`DSR`, plus `not_affected_included_DSR` and
  `not_affected_accuracy`) and `counts` (`TP`/`TN`/`FP`/`FN`/`inconclusive`/`error`/
  `not_found`/`TC`). Interpretation in `AGENTS.md` "Interpreting Metrics".
- `--raw-dir`: per-task `<run_id>.{prompt.txt,stdout,stderr,last.json,timing.json,
  timing.md,anonymized_targets.json}`.

Long-running experiment results are conventionally stored under
`/home/zhangxb/ClawSpace/results4ppt/<provider>/<project>/`; quick/local runs use
the gitignored `runs/`.

## Layout quick reference
- `codex_patch_presence_batch.py` - CLI entrypoint (thin shim over `codex_batch/`).
- `codex_batch/` - implementation package (see Architecture above).
- `prompts/` - agent contracts: `patch_presence.md` (base, symbol-friendly),
  `patch_presence_stripped_unbounded.md` (stripped binaries - the current default),
  `patch_presence_deployed.md` (distro packages with `not_affected` reasoning).
- `utils/safe_objdump.py` + `utils/config.json` - bounded disassembler + caps.
- `model_config.json` - fixed model/provider config.
- `metadata/` - deprecated generation scripts + their `.behavior.json` products.
- `analysis/` - written-up comparisons and per-CVE deep dives (Markdown + JSON).
- `runs/` - local experiment outputs (gitignored).
- `/home/zhangxb/extdisk/dataset4ppt/<project>/` - datasets (exports + binaries).
