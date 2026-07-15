# AGENTS.md

This file is the handoff guide for agents and humans running
`straight_detect` on another machine. If a user asks how to run an experiment
and does not already know the patch-presence workflow, first ask for the run
configuration listed in "Minimum Questions" below. Do not start by explaining
binary-analysis details.

## Repository Purpose

`straight_detect` runs patch-presence detection over target binaries by
launching one or more `codex exec` tasks. For each CVE/binary testcase, the
agent decides whether the patch-relevant security behavior is:

- `present`
- `absent`
- `not_affected`
- `inconclusive`
- `not_found`
- `error`

The repository code does not do the binary reasoning itself. It prepares
prompts, anonymizes target files, invokes `codex exec`, captures raw logs,
parses the model's JSON answer, merges results, and computes metrics.

Important entry points:

- `codex_patch_presence_batch.py`: main CLI wrapper.
- `codex_batch/`: implementation package.
- `prompts/`: prompt templates.
- `utils/safe_objdump.py`: bounded objdump helper exposed to the model.
- `model_config.json`: fixed model/provider config file.
- `metadata/`: scripts for creating patch-focused metadata.
- `analysis/`: local analysis reports.

The upstream remote currently used by this repo is:

```bash
git remote -v
```

Expected origin:

```text
git@github.com:akaganeite/CodexPPT.git
```

## Minimum Questions

When a user only says "help me run this code" or "run this project", ask for
these fields first:

- What project? Example: `curl`, `openssl`, `ffmpeg`, `binutils`, `libxml2`,
  `imagemagick`.
- Where is the dataset project directory? Example:
  `/home/USER/extdisk/dataset4ppt/openssl`.
- Which compiler and optimization suffix? Example: `gcc` and `O0`/`O2`/`O3`.
- Which model profile? Example: `codex_default`, `cliproxy_gpt55_medium`,
  `dpsk_flash`, `pptagent_glm52`, `volc_glm52`.
- Which reasoning setting? Inherit from profile, or override with
  `--reasoning-effort low|medium|high|xhigh`.

After receiving these answers, the agent should inspect the dataset path on
its own to discover the remaining files instead of asking the user. From the
dataset directory, resolve the following automatically:

- Target binary directory: `<dataset>/binaries/target/<project>_stripped`.
- Behavior JSON: `<dataset>/exports/<project>_behavior.json`. This is the
  required `--project-json` input for detection runs.
- Testset JSON: `<dataset>/exports/testset.json` or a subset such as
  `<dataset>/exports/pretest.pick.json`.
- Groundtruth JSON: `<dataset>/exports/groundtruth_with_not_affected.json`.
- Prompt template: for stripped binaries use
  `prompts/patch_presence_stripped_unbounded.md`.

Run the dataset format checks described later in this file to confirm the
files exist and are valid before proceeding.

### Pre-run smoke test workflow

Before launching any full experiment, the agent must run a smoke test to
verify the environment and model backend work correctly. Follow this sequence:

1. **Single-case test.** Run the wrapper with `--limit 1 --jobs 1` on one CVE
   from the testset. Confirm the model returns a valid status (not `error`)
   and that timing/output files are written correctly.

2. **Six-case concurrent test.** If the single-case test passes, run the
   wrapper with `--limit 6 --jobs 6` to verify that six `codex exec` tasks
   run in parallel without conflicts or backend failures.

3. **Report to user.** If all six cases return valid results, report the
   smoke-test summary to the user and present the full experiment command.
   Tell the user that, given the current conditions, a full-scale run is
   ready to execute.

Only after the smoke tests pass should the agent propose or run the full
experiment command. If any smoke-test case fails, diagnose the issue first
(see "Quick Troubleshooting") and fix it before retrying.

## Required Environment

Install or make available:

- Python 3.10+.
- `codex` CLI on `PATH`, or pass `--codex-bin /path/to/codex`.
- Standard binary utilities used by the model through shell commands:
  `file`, `strings`, `readelf`, `nm`, `objdump`, `rg`.
- `jq` for local dataset checks.
- Model/API credentials needed by the selected profile.

Run commands from the repository root:

```bash
cd /home/USER/ClawSpace/agent/straight_detect
```

The wrapper intentionally rejects layouts where `--groundtruth-json` is inside
the model-visible `--target-dir` or `--cd` directory. The model must not be able
to read the answer key.

## Model Configuration

All model/provider configuration lives in:

```text
/home/USER/ClawSpace/agent/straight_detect/model_config.json
```

There is no CLI flag for another config path. The code always loads this file.
This file is machine-local configuration: endpoint URLs, aliases, API-key
environment variables, and even available profiles may differ across machines.
Do not assume another user's `model_config.json` is identical to the one in the
current checkout. When moving to a new machine, inspect or create this file
first.

If Codex is already configured on the local machine, `codex_default` is the
recommended default profile for smoke tests. It lets `codex exec` inherit the
machine's existing Codex CLI model/provider/auth settings, so it is usually the
lowest-friction way to verify that the dataset, wrapper, prompts, and output
paths work before testing custom providers.

When a user asks about model settings or says to use the default configuration,
first inspect the current local Codex default model/provider/reasoning settings.
Then tell the user what default will actually be used and ask whether they agree
to run with it. Do not silently assume that `codex_default` means the same model
on every machine.

Top-level shape:

```json
{
  "active_profile": "codex_default",
  "aliases": {
    "openai": "codex_default"
  },
  "profiles": {
    "codex_default": {
      "provider": "codex",
      "reasoning": {"mode": "inherit"}
    }
  }
}
```

Profile fields:

- `provider`: use `codex` to inherit the current Codex CLI config; use
  `openai` for OpenAI-compatible Responses endpoints; use
  `volcengine-agent-plan` for the Volcengine agent-plan route.
- `base_url`: endpoint URL for non-`codex` providers.
- `wire_api`: usually `responses`.
- `model`: model name passed to `codex exec --model`.
- `api_key_env`: environment variable containing the API key.
- `requires_openai_auth`: `true` when the endpoint expects Codex/OpenAI auth
  instead of an explicit `env_key`.
- `codex_provider_name`: optional provider name injected into Codex config.
- `reasoning.mode`: `inherit`, `on`, or `off`.
- `reasoning.effort`: required when `mode` is `on`; one of `low`, `medium`,
  `high`, `xhigh`.

To add a model, add a new object under `profiles`, optionally add a short name
under `aliases`, then run with:

```bash
--model-profile your_new_profile
```

The deprecated `--provider NAME` flag still works only as an alias lookup in
`model_config.json`. New commands should use `--model-profile`.

Example profile:

```json
{
  "profiles": {
    "cliproxy_gpt55_medium": {
      "provider": "openai",
      "api_key_env": ["PPTAGENT_API_KEY"],
      "base_url": "http://127.0.0.1:8317/v1",
      "wire_api": "responses",
      "model": "gpt-5.5",
      "reasoning": {
        "mode": "on",
        "effort": "medium"
      }
    }
  }
}
```

If `reasoning.mode` is `off`, the wrapper does not append
`model_reasoning_effort`. If `reasoning.mode` is `on`, it appends:

```bash
-c 'model_reasoning_effort="medium"'
```

with the configured effort. A CLI `--reasoning-effort` overrides the profile.

## Dataset Layout

ask user where is the dataset project directory?
You may receive a packed .tar.gz file, unzip it first.

Expected project layout:

```text
<dataset>/<project>/
  exports/
    <project>_behavior.json
    <project>_metadata.json
    <project>_reference.json
    testset.json
    testset.gcc-O0.json
    testset.gcc-O2.json
    testset.gcc-O3.json
    groundtruth.json
    groundtruth_with_not_affected.json
    groundtruth.gcc-O0.json
    groundtruth.gcc-O2.json
    groundtruth.gcc-O3.json
    not_affected.json
  binaries/
    target/
      <project>_stripped/
      <project>_debug/
    reference/
  RCA/
  Diff/
  log/
```

Not every project has every optional file, but a normal detection run needs:

- `exports/<project>_behavior.json`
- `exports/testset.json` or a selected subset testset
- `exports/groundtruth_with_not_affected.json`
- `binaries/target/<project>_stripped` or another target directory

The `--project-json` argument must point to `<project>_behavior.json`, not a
plain `<project>_metadata.json`. The behavior JSON is the patch-presence input
because it includes the root-cause, patch-intent, and behavior-change
annotations used by the prompt. If only `<project>_metadata.json` exists, stop
and generate or copy the matching behavior JSON before running detection.

### Deployed Dataset Layout

Deployed-package datasets may live under a nested project root such as:

```text
/home/USER/extdisk/dataset4ppt/deployed/openssl/
  exports/
    openssl_behavior.json
    openssl_metadata.json
    openssl_reference.json
    testset.ubuntu-amd64.json
    groundtruth.ubuntu-amd64.json
  binaries/
    target/
      openssl_stripped/
        <canonical-binary-name>-deployed
  deployed/
    audit/
    input/
    logs/
    state/
    trace/
```

For deployed datasets, use `prompts/patch_presence_deployed.md`. The
`--project-json` file must still be `<project>_behavior.json`. Do not run
detection with `<project>_metadata.json` as a substitute. If a deployed dataset
is missing `<project>_behavior.json`, generate it or copy it from the
corresponding source-built dataset when the CVE set matches, for example:

```bash
cp /home/USER/extdisk/dataset4ppt/openssl/exports/openssl_behavior.json \
  /home/USER/extdisk/dataset4ppt/deployed/openssl/exports/openssl_behavior.json
```

Use the deployed testset and groundtruth files directly:

```text
exports/testset.ubuntu-amd64.json
exports/groundtruth.ubuntu-amd64.json
```

### JSON Meanings

`<project>_behavior.json`:

- Object keyed by CVE ID.
- Passed into the prompt as patch-focused metadata.
- Important fields include:
  `project`, `cve_id`, `cwe`, `vulnerability_description`,
  `patch_commit_message`, `patch_hunk`, `functions`, `function_anchors`,
  `reduced_function_code`, `root_cause_analysis`,
  `patch_intent_analysis`, and `behavior_changes` under patch intent.

`testset.json`:

- Top-level JSON array.
- Each item is one CVE and lists canonical binary names without compiler/opt.
- Accepted item shapes:

```json
[
  {
    "CVE": "CVE-2014-3572",
    "functions": ["ssl3_get_key_exchange"],
    "binaries": [
      "openssl-0.9.8zc-openssl",
      "openssl-1.0.0o-openssl"
    ]
  }
]
```

or:

```json
[
  {
    "CVE": "CVE-2014-3572",
    "functions": ["ssl3_get_key_exchange"],
    "vuln": ["openssl-0.9.8zc-openssl"],
    "patch": ["openssl-1.1.0-openssl"],
    "not_affected": []
  }
]
```

`groundtruth_with_not_affected.json`:

- Top-level JSON array.
- The evaluator uses this after the run finishes.
- It is never passed to `codex exec`.
- Fields:
  - `CVE`: CVE ID.
  - `functions`: patch-relevant function names.
  - `vuln`: binaries whose correct decision is `absent`.
  - `patch`: binaries whose correct decision is `present`.
  - `not_affected`: binaries whose correct decision is `not_affected`.

Target binaries:

- Testset and groundtruth use canonical names such as
  `openssl-1.0.1j-openssl`.
- Source-built target files usually add compiler and optimization suffixes,
  such as `openssl-1.0.1j-openssl-gcc-O2`.
- The wrapper resolves names by checking:
  1. `<target-dir>/<canonical-name>`
  2. `<target-dir>/<canonical-name>-deployed`
  3. `<target-dir>/<canonical-name>-<compiler>-<opt>`
- `--opt o2` is normalized to `O2` for filenames.

Legacy top-level object formats like `{"CVE-...": ["binary"]}` are no longer
supported by the current `codex_batch/testset.py`.

## Extracting a Dataset Archive

If another machine receives a compressed dataset archive, extract it so the
project root becomes:

```text
/home/USER/extdisk/dataset4ppt/<project>
```

Examples:

```bash
mkdir -p /home/USER/extdisk/dataset4ppt
tar -xf openssl_dataset4ppt.tar.gz -C /home/USER/extdisk/dataset4ppt
```

```bash
mkdir -p /home/USER/extdisk/dataset4ppt
unzip openssl_dataset4ppt.zip -d /home/USER/extdisk/dataset4ppt
```

After extraction, check the top-level directory:

```bash
find /home/USER/extdisk/dataset4ppt/openssl -maxdepth 3 -type d | sort | head -80
find /home/USER/extdisk/dataset4ppt/openssl/exports -maxdepth 1 -type f | sort
```

## Dataset Format Checks

Set variables first:

```bash
PROJECT=openssl
DATASET=/home/USER/extdisk/dataset4ppt/$PROJECT
TARGET=$DATASET/binaries/target/${PROJECT}_stripped
COMPILER=gcc
OPT=O2
```

Check required files and directories:

```bash
test -f "$DATASET/exports/${PROJECT}_behavior.json"
test -f "$DATASET/exports/testset.json"
test -f "$DATASET/exports/groundtruth_with_not_affected.json"
test -d "$TARGET"
```

Check behavior JSON is an object keyed by CVE:

```bash
jq -e 'type == "object" and (keys | length > 0)' \
  "$DATASET/exports/${PROJECT}_behavior.json"
```

Check testset export-list format:

```bash
jq -e '
  type == "array" and
  all(.[]; (.CVE | type == "string") and
    (
      (.binaries | type == "array") or
      ((.vuln | type == "array") and (.patch | type == "array") and ((.not_affected // []) | type == "array"))
    )
  )
' "$DATASET/exports/testset.json"
```

Check groundtruth export-list format:

```bash
jq -e '
  type == "array" and
  all(.[]; (.CVE | type == "string") and
    (.vuln | type == "array") and
    (.patch | type == "array") and
    ((.not_affected // []) | type == "array")
  )
' "$DATASET/exports/groundtruth_with_not_affected.json"
```

Check that every requested target binary resolves to a file:

```bash
jq -r '.[].binaries[]?' "$DATASET/exports/testset.json" | sort -u |
while read -r b; do
  if [ ! -f "$TARGET/$b" ] && [ ! -f "$TARGET/$b-$COMPILER-$OPT" ]; then
    echo "missing target: $b or $b-$COMPILER-$OPT"
  fi
done
```

If the testset uses `vuln`/`patch`/`not_affected` instead of `binaries`, use:

```bash
jq -r '.[] | (.vuln[]?, .patch[]?, .not_affected[]?)' "$DATASET/exports/testset.json" | sort -u |
while read -r b; do
  if [ ! -f "$TARGET/$b" ] && [ ! -f "$TARGET/$b-$COMPILER-$OPT" ]; then
    echo "missing target: $b or $b-$COMPILER-$OPT"
  fi
done
```

## Running Experiments

Use `--binarywise` for the current experiments unless the user explicitly asks
for one `codex exec` to see multiple binaries at once.

Stripped-binary GPT/Codex default example:

```bash
cd /home/USER/ClawSpace/agent/straight_detect
RUN_ID=$(date +%Y%m%d_%H%M%S)

python3 codex_patch_presence_batch.py \
  --project-json /home/USER/extdisk/dataset4ppt/openssl/exports/openssl_behavior.json \
  --testset-json /home/USER/extdisk/dataset4ppt/openssl/exports/testset.json \
  --target-dir /home/USER/extdisk/dataset4ppt/openssl/binaries/target/openssl_stripped \
  --groundtruth-json /home/USER/extdisk/dataset4ppt/openssl/exports/groundtruth_with_not_affected.json \
  --compiler gcc \
  --opt O2 \
  --output /home/USER/ClawSpace/results4ppt/codexgpt/openssl/binarywise_o2_stripped_gpt_${RUN_ID}_results.json \
  --raw-dir /home/USER/ClawSpace/results4ppt/codexgpt/openssl/binarywise_o2_stripped_gpt_${RUN_ID}_raw \
  --prompt-template /home/USER/ClawSpace/agent/straight_detect/prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --model-profile codex_default \
  --codex-json-events \
  --jobs 4 \
  --timeout 3600
```

Single CVE smoke test:

```bash
python3 codex_patch_presence_batch.py \
  --project-json /home/USER/extdisk/dataset4ppt/ffmpeg/exports/ffmpeg_behavior.json \
  --testset-json /home/USER/extdisk/dataset4ppt/ffmpeg/exports/pretest.pick.json \
  --target-dir /home/USER/extdisk/dataset4ppt/ffmpeg/binaries/target/ffmpeg_stripped \
  --groundtruth-json /home/USER/extdisk/dataset4ppt/ffmpeg/exports/groundtruth_with_not_affected.json \
  --compiler gcc \
  --opt O2 \
  --output /tmp/ffmpeg_smoke_results.json \
  --raw-dir /tmp/ffmpeg_smoke_raw \
  --prompt-template /home/USER/ClawSpace/agent/straight_detect/prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --model-profile cliproxy_gpt55_medium \
  --codex-json-events \
  --jobs 1 \
  --limit 1 \
  --timeout 3600
```

Resume and retry only previous errors:

```bash
python3 codex_patch_presence_batch.py \
  --project-json /home/USER/extdisk/dataset4ppt/openssl/exports/openssl_behavior.json \
  --testset-json /home/USER/extdisk/dataset4ppt/openssl/exports/testset.json \
  --target-dir /home/USER/extdisk/dataset4ppt/openssl/binaries/target/openssl_stripped \
  --groundtruth-json /home/USER/extdisk/dataset4ppt/openssl/exports/groundtruth_with_not_affected.json \
  --compiler gcc \
  --opt O2 \
  --output /home/USER/ClawSpace/results4ppt/codexgpt/openssl/binarywise_o2_stripped_gpt_RESULTS.json \
  --raw-dir /home/USER/ClawSpace/results4ppt/codexgpt/openssl/binarywise_o2_stripped_gpt_raw \
  --prompt-template /home/USER/ClawSpace/agent/straight_detect/prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --model-profile codex_default \
  --codex-json-events \
  --jobs 4 \
  --resume \
  --retry-errors \
  --timeout 3600
```

Useful flags:

- `--cve CVE-...`: restrict to one CVE; repeatable.
- `--limit N`: run only the first `N` selected CVEs.
- `--dry-run`: write prompts and schema without calling the model.
- `--jobs N`: concurrent `codex exec` tasks.
- `--resume`: skip completed entries already in `--output`.
- `--retry-errors`: with `--resume`, rerun entries with status `error`.
- `--no-anonymize-targets`: expose original filenames to the model. Avoid this
  unless debugging; default anonymization is preferred.

## Prompt Selection

- `prompts/patch_presence.md`: normal prompt for symbol-friendly local
  experiments.
- `prompts/patch_presence_stripped_unbounded.md`: stripped-binary prompt. Use
  this for `*_stripped` target directories.
- `prompts/patch_presence_deployed.md`: deployed-package prompt with
  `not_affected` reasoning.

For dataset4ppt stripped experiments, default to
`patch_presence_stripped_unbounded.md`.

## Output Layout

Prefer storing long-running experiment results under:

```text
/home/USER/ClawSpace/results4ppt/
  codexgpt/<project>/
  codexdpsk/<project>/
  codexglm/<project>/
  pptagent/<project>/
```

Some older paths may use `result4ppt` singular. Check both if looking for
historical runs:

```bash
find /home/USER/ClawSpace/results4ppt /home/USER/ClawSpace/result4ppt -maxdepth 3 -type d 2>/dev/null
```

A typical Codex run has:

```text
<run>_results.json
<run>_results.json.metrics.json
<run>_raw/
  single_cve_schema.json
  CVE-...__binary.prompt.txt
  CVE-...__binary.stdout
  CVE-...__binary.stderr
  CVE-...__binary.last.json
  CVE-...__binary.timing.json
  CVE-...__binary.timing.md
  CVE-...__binary.anonymized_targets.json
```

Merged result JSON shape:

```json
{
  "CVE-2014-3572": {
    "openssl-0.9.8zc-openssl": {
      "status": "absent",
      "confidence": "high",
      "reasoning": "...",
      "evidence": ["..."]
    }
  }
}
```

Metrics JSON shape:

```json
{
  "metrics": {
    "A": 0.97,
    "P": 0.98,
    "R": 0.96,
    "F1": 0.97,
    "DSR": 0.89,
    "not_affected_included_DSR": 0.88,
    "not_affected_accuracy": 0.75
  },
  "counts": {
    "TP": 50,
    "TN": 68,
    "FP": 1,
    "FN": 2,
    "inconclusive": 5,
    "error": 6,
    "not_found": 0,
    "TC": 132
  },
  "mismatches": []
}
```

Raw files:

- `.prompt.txt`: exact prompt sent to `codex exec`.
- `.stdout`: JSON event stream when `--codex-json-events` is enabled.
- `.stderr`: Codex CLI stderr and backend errors.
- `.last.json`: final model message captured by `--output-last-message`.
- `.timing.json`: parsed timing and token usage from JSON events.
- `.timing.md`: human-readable timing table.
- `.anonymized_targets.json`: mapping from anonymous filenames like
  `target_001` back to original binary names.

Timing files are most useful when `--codex-json-events` is enabled. Without it,
the wrapper can still record wall time, but detailed turns, token usage, and
command executions may be empty.

## Interpreting Metrics

Binary status mapping:

- Groundtruth `vuln` expects model status `absent`.
- Groundtruth `patch` expects model status `present`.
- Groundtruth `not_affected` expects model status `not_affected`.

Standard binary metrics:

- `TP`: patched binary correctly predicted `present`.
- `TN`: vulnerable binary correctly predicted `absent`.
- `FP`: vulnerable binary predicted `present`.
- `FN`: patched binary predicted `absent`.
- `A`, `P`, `R`, `F1`: computed over decisive `present`/`absent` decisions.
- `DSR`: decisive success rate for binary patch/vuln decisions.

Ternary/not-affected metrics:

- `not_affected_accuracy`: correct `not_affected` predictions divided by
  total groundtruth `not_affected` cases.
- `not_affected_included_DSR`: decisive/correct rate when not-affected cases
  are included in the total.

`inconclusive`, `error`, and `not_found` are not correct detections and lower
DSR-like rates.

## Safety and Data Leakage Rules

- Do not place groundtruth inside `--target-dir`.
- Do not make `--cd` point at a directory that contains groundtruth.
- Prefer the default anonymization. It copies only the selected target binary
  into a temporary directory as `target_001`, then remaps results after the run.
- Do not let the model inspect source trees, diff files, dataset exports, or
  answer keys during detection.
- The prompt already instructs the model not to use version banners as patch
  evidence. Keep this restriction.

## Quick Troubleshooting

`prompt template does not exist`:

- Use an absolute prompt path, or run from repo root.
- For stripped experiments:
  `/home/USER/ClawSpace/agent/straight_detect/prompts/patch_presence_stripped_unbounded.md`.

Metrics are all zero:

- Usually the output binary names do not match groundtruth names, or
  `groundtruth_json` is in an unsupported format.
- Check that testset/groundtruth are export-list arrays.
- Check `--compiler` and `--opt` match target filenames.

Many `error` statuses:

- Open `.stderr` and `.last.json` for a sample testcase.
- Backend JSON/schema incompatibility often shows up as invalid final JSON.
- API/network/proxy failures usually appear in `.stderr`.
- Timeout appears in `.stderr` as a killed process after `--timeout`.

No token/tool details in timing:

- Add `--codex-json-events`.
- Some backends/proxies may not emit complete Codex JSON event usage.

Lots of missing binaries:

- Re-run the binary resolution check in "Dataset Format Checks".
- Confirm whether target filenames are canonical or suffixed with
  `-gcc-O0`, `-gcc-O2`, or `-gcc-O3`.

Interrupted run:

- Use the same `--output` and `--raw-dir` with `--resume`.
- Add `--retry-errors` if the previous output contains `error` statuses to
  rerun.

## Metadata Pipeline Notes

The detection prompt uses behavior metadata produced before binary detection.
Relevant scripts live under `metadata/`:

- `project_source_analysis.py`: builds patch-focused source context and
  reduced function information from project CVE metadata.
- `generate_behavior_analysis_deepseek.py`: calls DeepSeek to add
  `root_cause_analysis`, `patch_intent_analysis`, and behavior changes.
- `run_metadata_pipeline.py`: orchestrates metadata generation.

For most experiment runs, do not regenerate metadata. Use the exported
`<project>_behavior.json` already present in the dataset's `exports/`
directory.
