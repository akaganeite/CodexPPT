# straight_detect - Binary Patch-Presence Detection

`straight_detect` runs an LLM agent through `codex exec` to perform
**patch-presence detection** on binaries. For each CVE/binary pair, the agent
decides whether the relevant patch is `present`, `absent`, `not_affected`,
`inconclusive`, or `not_found`.

The agent performs the actual binary reasoning. This repository provides the
Python wrapper that builds prompts, schedules batch jobs, anonymizes target
binaries, parses and validates JSON answers, and computes metrics against
ground truth.

The main entry point is `codex_patch_presence_batch.py`, a thin wrapper around
the `codex_batch/` package. See `CLAUDE.md` for implementation-level notes.

## Detection Rules

These rules are embedded in the prompt and are enforced as part of the agent
contract:

- Do not use network access.
- Do not use version strings, release banners, package labels, or embedded
  `curl x.y.z`-style strings as patch evidence.
- Do not inspect source files referenced by metadata, DWARF paths, debug paths,
  or diff paths.
- Base every decision on local binary evidence and explicit reasoning.
- Only use binaries under `--target-dir` plus the supplied `safe_objdump`
  helper.

## Configuration

Install and configure the following before running a batch:

- Python 3.10+.
- A working `codex` CLI available on `PATH`, or pass its path with
  `--codex-bin`.
- Valid Codex/OpenAI credentials when using `--provider openai`.
- For DeepSeek-compatible runs, a local OpenAI-compatible proxy endpoint and
  `--provider dpsk --dpsk-base-url ...`.
- For PPTAgent runs, set `PPTAGENT_API_KEY` or override the variable name with
  `--pptagent-api-key-env`.
- For Volcengine Ark runs, set `VOLC_AGENT_PLAN_API_KEY` or override the
  variable name with `--volc-api-key-env`.
- Project metadata JSON, usually
  `metadata/<project>/*_project_source_analysis.behavior.json`.
- Dataset export-list `testset.json` and `groundtruth.json`.
- A target binary directory passed with `--target-dir`.

Important path constraint: `--groundtruth-json` must be outside both
`--target-dir` and the `--cd` directory passed to `codex exec`. The wrapper
rejects unsafe layouts so the agent cannot read the answer key.

## Quick Start

Run commands from the repository root. This example evaluates stripped curl
binaries with the default Codex/OpenAI provider in binarywise mode:

```bash
python3 codex_patch_presence_batch.py \
  --project-json metadata/curl/curl_project_source_analysis.behavior.json \
  --testset-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/testset.json \
  --target-dir /home/zhangxb/extdisk/dataset4ppt/curl/binaries/target/curl_stripped \
  --groundtruth-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/groundtruth_with_not_affected.json \
  --opt o0 \
  --output runs/curl_stripped_o0_results.json \
  --raw-dir runs/curl_stripped_o0_raw \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --provider openai \
  --codex-json-events \
  --timeout 3600
```

Useful flags:

- `--jobs N`: run `N` concurrent `codex exec` tasks. The default is `1`.
  Higher values improve throughput but increase rate-limit risk.
- `--resume`: skip tasks already present in `--output`.
- `--retry-errors`: with `--resume`, rerun tasks whose previous result contains
  `status=error`.
- `--dry-run`: write prompts without calling the model.
- `--limit` and `--cve`: restrict the run to a smaller subset.
- `--binarywise`: run one `codex exec` per CVE/binary pair instead of one
  `codex exec` per CVE.
- `--codex-json-events`: pass `--json` to `codex exec` while still reading the
  final message from `--output-last-message`.

With `--jobs > 1`, the progress prefix `[i/total]` reports launch order, not
completion order. Output write order is not deterministic, but completed tasks
are merged by key and are safe to resume after interruption.

## Providers

`--provider` selects how `codex exec` is routed:

- `openai`: use the current Codex/OpenAI configuration unchanged.
- `dpsk`: route Codex through a local DeepSeek-compatible proxy.
- `pptagent`: route Codex through a PPTAgent OpenAI-compatible Responses
  endpoint.
- `volc`: route Codex directly to the Volcengine Ark Responses endpoint.

DeepSeek-compatible example:

```bash
python3 codex_patch_presence_batch.py \
  --project-json metadata/curl/curl_project_source_analysis.behavior.json \
  --testset-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/testset.json \
  --target-dir /home/zhangxb/extdisk/dataset4ppt/curl/binaries/target/curl_stripped \
  --groundtruth-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/groundtruth_with_not_affected.json \
  --opt o0 \
  --output runs/curl_stripped_o0_dpsk_results.json \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --provider dpsk \
  --dpsk-base-url http://127.0.0.1:18080/v1 \
  --dpsk-model deepseek-v4-flash \
  --reasoning-effort high \
  --codex-json-events \
  --timeout 3600
```

PPTAgent example:

```bash
python3 codex_patch_presence_batch.py \
  --project-json metadata/curl/curl_project_source_analysis.behavior.json \
  --testset-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/testset.json \
  --target-dir /home/zhangxb/extdisk/dataset4ppt/curl/binaries/target/curl_stripped \
  --groundtruth-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/groundtruth_with_not_affected.json \
  --opt o0 \
  --output runs/curl_stripped_o0_pptagent_results.json \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --provider pptagent \
  --pptagent-base-url http://192.168.104.61:4000/v1 \
  --pptagent-model glm-5.2 \
  --codex-json-events \
  --timeout 3600
```

## Data Format

`--testset-json` and `--groundtruth-json` only support the dataset export-list
format. The top-level JSON value must be a list.

Testset example:

```json
[
  {
    "CVE": "CVE-...",
    "functions": ["target_function"],
    "binaries": ["binary_name_1", "binary_name_2"]
  }
]
```

Ground-truth example:

```json
[
  {
    "CVE": "CVE-...",
    "vuln": ["binary_name_1"],
    "patch": ["binary_name_2"],
    "not_affected": []
  }
]
```

Legacy top-level object formats such as `CVE -> [binary]` and
`CVE -> {vuln, patch}` are no longer supported. The current experimental
dataset exports are expected under
`/home/zhangxb/extdisk/dataset4ppt/<project>/exports/`. Historical files under
`testset/` and `groundtruth/` are kept only for reference.

`--project-json` points to metadata generated by the offline metadata pipeline,
typically `metadata/<project>/*_project_source_analysis.behavior.json`. It
contains root-cause, patch-intent, and behavior-change information used by the
prompt.

## Outputs

Each run writes:

- `--output`: merged JSON results keyed by CVE or CVE/binary task.
- `--metrics-output`: metrics JSON. Defaults to `<output>.metrics.json`.
- `--raw-dir`: per-task prompts, stdout, stderr, and raw agent outputs.

The wrapper reports Accuracy, Precision, Recall, F1, and DSR. `not_affected`
counts as a decisive status, while `inconclusive`, `error`, and `not_found`
reduce DSR.

## Reference Results

| Project | PS3 A | PS3 P | PS3 R | PS3 F1 | PS3 DSR | React A | React P | React R | React F1 | React DSR | BinXray A | BinXray P | BinXray R | BinXray F1 | BinXray DSR | PatchDiscovery A | PatchDiscovery P | PatchDiscovery R | PatchDiscovery F1 | PatchDiscovery DSR | Robin A | Robin P | Robin R | Robin F1 | Robin DSR | Ours A | Ours P | Ours R | Ours F1 | Ours DSR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Binutils | 0.74 | 0.86 | 0.77 | 0.81 | 0.63 | 0.67 | 0.51 | 0.88 | 0.64 | 0.41 | 0.89 | 0.97 | 0.87 | 0.92 | 0.72 | 0.78 | 0.95 | 0.73 | 0.83 | 0.75 | 0.90 | 0.87 | 0.80 | 0.83 | 0.18 | 0.92 | 0.92 | 0.97 | 0.94 | 0.87 |
