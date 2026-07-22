# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`claudeagent` is a **from-scratch, model-driven harness for binary patch presence testing**, designed independently in this repo (not a fork of the sibling `../pptagent` prototype, though it shares the same task contract). Given one project, one CVE, and one binary, a DeepSeek model uses bounded `binutils` observations to decide a verdict:

- `present` — the patch's semantics are present in the binary
- `absent` — the vulnerable (unpatched) behavior is present
- `not_affected` — this version/binary is outside the CVE's affected range
- `inconclusive` — evidence is insufficient

The verdict **must** be produced by the model calling a finalization tool after a controlled tool loop — never by a static, CVE-specific pattern matcher baked into the default path. The valuable artifacts are the prompt, the tool schema, typed observations, an evidence ledger, a schema-repair loop, the transcript, finalization, and batch metrics.

## Non-negotiable harness constraints

These come from `../AGENTS.md` and define what "correct" means here. Read that file before changing input handling, evidence flow, or verdict validation.

- **Model input is bounded.** The investigation model may see only: (1) the host-compiled PatchSpec and its exact metadata source excerpts, (2) the target binary itself, and (3) controlled `binutils` observations derived directly from that binary. Full CVE metadata and PatchSpec generation provenance remain host-side.
- **Never leak debug/source signals** into the model, transcript, evidence ledger, or default verdict validation. Forbidden as default inputs/evidence: sibling debug/unstripped artifacts (`curl_debug`, `.debug` files), local source repos (e.g. `~/extrepo/...`), source files, DWARF / source-line tables, `addr2line` source mapping, `objdump -S`, `readelf --debug-dump=*`. Humans may diagnose with these *outside* the harness, but such facts cannot become model input or final evidence.
- **Determinate verdicts must cite evidence.** `present` / `absent` / `not_affected` must reference concrete `evidence_id`s emitted by tools. Free-text-only evidence is rejected and returned to the model for repair rather than silently accepted.
- **Schema failures repair, not crash.** When the finalization payload fails schema validation, send the error back as tool output so the model can fix it, instead of ending the run.
- **Keep changes small and modular.** Prefer focused Python modules over one growing script; prefer stage-local edits over cross-cutting rewrites.

## Model configuration

DeepSeek via an OpenAI-compatible chat-completions endpoint.

- Default mode is **flash / non-thinking**: the request sets `thinking: {"type": "disabled"}` (no `reasoning_effort`). Only enable `thinking: {"type": "enabled"}` + `reasoning_effort` when a run explicitly asks for it.
- Auth: `DEEPSEEK_API_KEY` (already set in this environment), or an OpenAI-compatible `OPENAI_API_KEY` / `OPENAI_BASE_URL` pair. Load from a repo-local `.env` if present.
- Tool calling uses `tool_choice: "auto"`, `stream: false`.

## Default data paths

Unless a run overrides them, `<project>` is substituted with the current project name (currently only `curl`):

- Binaries root: `~/extdisk/dataset4ppt/<project>/binaries`
- curl testset / groundtruth exports: `/home/zhangxb/extdisk/dataset4ppt/curl/exports`
- curl metadata (behavior analysis): `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.behavior.json`

curl is currently the **only** supported testset.

## Reference implementation

`../pptagent` is a working prototype of the same task. Treat it as a reference for the prompt/tool-schema/loop/finalization/metrics shape — not as code to copy wholesale. Its module split (entrypoint → loop → tools → command policy → observations → runtime/ledger → finalization → schema utils → prompting → model client → host → batch) is a reasonable starting decomposition. Its `final_result.schema.json` shows the validated verdict shape (verdict + cited `evidence_ids`).

The upstream `openai/codex` agent loop lives at `../codex/codex` (note the doubled path); `../AGENTS.md` lists the source regions worth mining for prompt/tool-loop/turn/finalization patterns.

## Status

Working end-to-end. The harness is a lean tool loop (distilled from the codex agent loop) over a general policy-gated shell, reproducing what made direct `codex exec` detection effective.

### Architecture

Run all commands from the package parent (`/home/zhangxb/ClawSpace/codex`) so `claudeagent` imports resolve.

- **Loop** (`agent_loop.py`): build prompt → sample model → dispatch tool calls → feed bounded results back → repeat until `submit_detection_result` is accepted. Three bounded phases: explore (`--max-turns`, default 12) → finalize-nudge (`--finalization-turns`, default 3) → forced repair (≤2). Tool/schema failures repair in-band; only model-API failures (after retries) abort.
- **PatchSpec** (`patchspec/`): normalize source metadata into stable hunks, anchors, trusted OLD/NEW indicators, and model-generated advisory semantics. Generation is metadata-only, validated against exact JSON references, cached per metadata/model fingerprint, and never enters the binary evidence ledger.
- **Tools** (`tools.py`, `tools.json`): general `run_command` + `strings_grep` + `objdump_window` + `submit_detection_result`. Every successful command mints a typed observation (`obs_XXXX`) and one or more evidence-ledger items (`ev_XXXX`); the model cites those ids. "The observation is the citable evidence."
- **Policy** (`command_policy.py`): default-deny allowlist (binutils + safe filters), debug/source denylist, and **path confinement** — every path argument must resolve to the one target binary, so sibling `.debug`/source artifacts are blocked at the policy layer.
- **Finalize** (`decision.py`, `finalize.py`, `schemas/final_result.schema.json`): JSON-schema + evidence-id gate + behavior-scoped supports. Determinate verdicts need at least one support whose evidence ids exactly cover the cited ledger ids; support behavior refs and evidence polarity are validated before write. Failures return a repair payload, never crash.
- **Verdicts**: `present` / `absent` / `not_affected` / `inconclusive`. Default model mode is flash/non-thinking (`thinking:{type:disabled}`).

### Run a single case

```
python3 -m claudeagent.agent_loop \
  --cve-id CVE-2013-0249 \
  --metadata-json /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.behavior.json \
  --binary ~/extdisk/dataset4ppt/curl/binaries/target/curl_stripped/curl-7.29.0-libcurl-gcc-O0 \
  --output-dir /tmp/claudeagent_runs/case1
```

Add `--dry-run` to validate tool/result schemas, render the prompt, and run host preflight with no API call or writes. `--verbose` streams per-turn model messages to stderr. Other flags: `--model`, `--base-url`, `--env-file`, `--no-strict`, `--thinking`/`--reasoning-effort`, `--api-timeout`, `--api-max-retries`, `--no-finalize-on-max-turns`.

Generate or inspect a PatchSpec independently with `python3 -m claudeagent.patchspec --metadata-json <metadata.json> --cve-id <CVE> --output <patch_spec.json>`. Pass a prebuilt artifact to a case with `--patchspec-json`; otherwise the case lazily resolves `<output-dir>/patch_spec.json`.

Per-case artifacts in `--output-dir`: `final_result.json` (verdict + observations + evidence_ledger + harness_metrics + usage), `transcript.json`, `usage_metrics.json`.

### Run the curl batch

```
python3 -m claudeagent.batch --out-root /tmp/claudeagent_batch/run1 [--cve CVE-...] [--limit N] [--max-workers 4] [--dry-run]
```

Defaults: groundtruth `…/exports/groundtruth_with_not_affected.json` (364 cases), binaries `~/extdisk/dataset4ppt/curl/binaries` under variant `target/curl_stripped`, metadata behavior.json. Groundtruth maps vuln→absent, patch→present, not_affected→not_affected. Each case runs as an isolated subprocess. Writes per-case subdirs + `batch_metrics.json` (accuracy, 4-way confusion matrix, repair totals). `--dry-run` lists resolved cases and missing binaries without any API call.

### Tests

```
python3 -m claudeagent.tests.test_command_policy   # adversarial allow/deny + path confinement
python3 -m claudeagent.tests.test_finalize         # evidence-id gate, version reject, schema/repair
```

### Validated

Single-case: CVE-2013-0249 → `present` on patched (7.29.0) and `absent` on vulnerable (7.27.0), both high-confidence, evidence-cited, schema-valid. Batch: 6/6 (100%) on CVE-2013-0249's balanced cases.

### Known limitation

Because every successful command mints at least a `command_output` evidence id, behavior supports are still structurally rather than semantically checked at this stage. They prevent invented behavior/evidence references and reject pure no-match evidence for decisive sides, but `decisive_addresses` + `reasoning` remain the human-review anchors until the independent semantic verifier is enabled.
