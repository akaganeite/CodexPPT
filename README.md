# straight_detect

`straight_detect` evaluates whether a security patch is present in a target
binary. It prepares an isolated, anonymous binary, launches one or more
`codex exec` tasks, records the raw model interaction, validates the returned
JSON, and computes metrics against a ground-truth export.

The detector itself does not execute the target and does not infer a verdict
from a version string. The model must justify a decision with bounded static
evidence such as disassembly, control-flow structure, strings, and (when
enabled) the native Ghidra tools.

## Results and repository layout

Each testcase has one of these statuses:

- `present`: patch-relevant behavior is present.
- `absent`: the vulnerable behavior remains.
- `not_affected`: the testcase is outside the affected product/configuration.
- `inconclusive`: available evidence is insufficient.
- `not_found`: the expected target could not be resolved.
- `error`: the runner, model, or analysis service failed.

Important entry points:

```text
codex_patch_presence_batch.py  # command-line batch runner
codex_batch/                   # dataset, model, resume, and output logic
prompts/                       # normal, stripped, and deployed prompts
utils/safe_objdump.py          # bounded static-observation helper
codex_batch/ghidra_manager.py  # Ghidra cache and analysis lifecycle
codex_batch/ghidra_tools.py    # six read-only Ghidra tool implementations
codex_batch/ghidra_mcp.py      # stdio MCP service
requirements-ghidra.txt        # optional Ghidra dependencies
model_config.json.template     # copy to the ignored local configuration
```

## Requirements

Required for all runs:

- Python 3.10 or newer.
- `codex` on `PATH`, or an explicit `--codex-bin` path.
- `file`, `strings`, `readelf`, `nm`, `objdump`, and `rg`.
- `jq` for dataset checks.
- Credentials for the selected model/provider.

Ghidra runs additionally require a compatible Ghidra installation (the tested
layout is Ghidra 11.4.2) and the optional packages listed in
`requirements-ghidra.txt`:

```bash
python3 -m pip install -r requirements-ghidra.txt
```

The runner uses a read-only Codex sandbox. Target copies are anonymized and
made non-executable before they are exposed to the model.

## Model configuration

The repository intentionally does not track a machine-specific
`model_config.json`. Create it once in the repository root:

```bash
cp model_config.json.template model_config.json
${EDITOR:-vi} model_config.json
```

The local file is ignored by Git. Never put API keys directly in the JSON;
use an environment variable named by `api_key_env`.

The template demonstrates three supported provider forms:

- `codex`: inherit the current Codex CLI configuration.
- `openai`: use an OpenAI-compatible Responses endpoint such as CLIProxy.
- `volcengine-agent-plan`: use a Volcengine agent-plan endpoint when present
  in a local configuration.

Select a profile with `--model-profile PROFILE`. A command-line
`--reasoning-effort low|medium|high|xhigh|max` override takes precedence over
the profile. For example, a local CLIProxy profile can be used with:

```bash
export PPTAGENT_API_KEY='...'
python3 codex_patch_presence_batch.py ... \
  --model-profile cliproxy_terra_high \
  --reasoning-effort high
```

The runner always reads the root `model_config.json`; it does not accept an
arbitrary config path. Keep provider names, endpoint URLs, and model aliases
machine-local.

## Dataset contract

For a project directory such as `/data/dataset4ppt/openssl`, the usual layout
is:

```text
openssl/
  exports/
    openssl_behavior.json
    testset.json                 # or testset.gcc-O2.json, etc.
    groundtruth_with_not_affected.json
  binaries/target/
    openssl_stripped/
    openssl_debug/               # optional separated debug files
```

`<project>_behavior.json` is an object keyed by CVE and supplies the
patch-focused metadata used in the prompt. `testset*.json` and
`groundtruth*.json` are export-list arrays. A testset entry may contain a
`binaries` list, or `vuln`, `patch`, and `not_affected` lists. Ground truth is
never passed to the model.

Before a run, verify the required files and target resolution:

```bash
PROJECT=openssl
DATASET=/data/dataset4ppt/$PROJECT
test -f "$DATASET/exports/${PROJECT}_behavior.json"
test -f "$DATASET/exports/testset.json"
test -f "$DATASET/exports/groundtruth_with_not_affected.json"
test -d "$DATASET/binaries/target/${PROJECT}_stripped"
jq -e 'type == "object" and (keys | length > 0)' \
  "$DATASET/exports/${PROJECT}_behavior.json"
```

Target names are resolved in this order: canonical name, canonical name with
`-deployed`, and canonical name with the selected compiler/optimization suffix
(for example `-gcc-O2`). If `--debug-dir` is supplied, matching debug files
are merged into per-run temporary copies with `eu-unstrip`.

Do not put the ground-truth file under `--target-dir` or `--cd`. That would
break the model isolation boundary.

## Metadata modes and prompts

The behavior export can be rendered with `--metadata full` or
`--metadata shim`:

- `full` keeps function anchors, reduced function code, root-cause analysis,
  patch-intent analysis, and behavior-change annotations.
- `shim` keeps the compact patch description, patch hunk, function names, and
  other identifying fields while removing those richer analysis fields.

Use the matching prompt template for the selected binary type:

```text
prompts/patch_presence.md                    # symbol-friendly local runs
prompts/patch_presence_stripped_unbounded.md  # stripped source-built runs
prompts/patch_presence_deployed.md            # deployed-package runs
```

The prompt asks the model to distinguish patch evidence from compiler,
version, or unrelated-string evidence. It forbids target execution, GDB,
process launch, and source/ground-truth inspection.

## Native Ghidra tools

Ghidra is optional and is disabled by default:

```text
--ghidra off|auto|on             default: off
--ghidra-cache-dir PATH          default: ~/.cache/straight_detect/ghidra
--ghidra-install-dir PATH       optional installation override
--ghidra-timeout SECONDS        default: 900
```

Installation discovery checks `--ghidra-install-dir`, then
`GHIDRA_INSTALL_DIR`, then the known local Ghidra 11.4.2 layout, and finally
pyghidra automatic discovery. After anonymization (and optional
`eu-unstrip`), the runner hashes the actual analysis file with SHA-256.
Each hash has an independent cache directory and file lock:

```text
~/.cache/straight_detect/ghidra/<sha256>/
  project/     # Ghidra project data
  index/       # persisted indexes
  metadata.json
  state.json
```

Only a cache entry with matching schema, binary hash, Ghidra/pyghidra version,
and `ready` state is reused. Failed or incomplete entries can be rebuilt.

When available, one MCP server is bound to the current testcase's anonymous
binary. Other user MCP servers are not exposed to that `codex exec` process;
the enabled tool list is fixed to:

```text
ghidra_locate_function(strings, calls, constants, field_offsets, max_candidates)
ghidra_function_summary(function)
ghidra_cfg_slice(function, address, radius_blocks)
ghidra_path_probe(function, from_address, to_address, require_patterns, forbid_patterns)
ghidra_call_args(function, call_address)
ghidra_decompile_slice(function, address, max_lines)
```

The tools accept only bounded query parameters and the current anonymous
binary. They return raw-first observations (`ok`, `observation_id`, bounded
instructions/CFG/P-code, `parsed_facts`, errors, and evidence objects).
Decompilation is advisory and cannot replace raw instructions or CFG evidence
for a deterministic conclusion.

Mode behavior:

- `off`: no analysis, cache preparation, or MCP server.
- `auto`: try Ghidra; on failure hide the six tools and continue with objdump.
- `on`: a preparation or MCP failure marks that testcase `error` without
  calling the model; other testcases continue.

`--dry-run` validates dependencies, paths, and configuration without doing
the expensive Ghidra analysis.

## Running a binarywise experiment

The following is a complete stripped-binary example. Adjust paths, model
profile, and testset for the project being evaluated:

```bash
cd /home/USER/ClawSpace/agent/straight_detect
PROJECT=openssl
DATASET=/home/USER/dataset4ppt/$PROJECT
RUN_ID=$(date +%Y%m%d_%H%M%S)

python3 codex_patch_presence_batch.py \
  --project-json "$DATASET/exports/${PROJECT}_behavior.json" \
  --testset-json "$DATASET/exports/testset.gcc-O2.json" \
  --target-dir "$DATASET/binaries/target/${PROJECT}_stripped" \
  --groundtruth-json "$DATASET/exports/groundtruth_with_not_affected.gcc-O2.json" \
  --compiler gcc \
  --opt O2 \
  --output "/home/USER/results4ppt/codexgpt/$PROJECT/${RUN_ID}_results.json" \
  --raw-dir "/home/USER/results4ppt/codexgpt/$PROJECT/${RUN_ID}_raw" \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --metadata full \
  --binarywise \
  --model-profile codex_default \
  --codex-json-events \
  --ghidra off \
  --jobs 4 \
  --timeout 3600
```

For a Ghidra-enabled run, replace the Ghidra and model options as needed:

```bash
  --model-profile cliproxy_terra_high \
  --ghidra on \
  --ghidra-cache-dir /home/USER/.cache/straight_detect/ghidra \
  --ghidra-install-dir /home/USER/tools/ghidra_11.4.2_PUBLIC \
  --ghidra-timeout 900
```

Useful selection and recovery flags include:

```text
--limit N                  run only the first N selected CVEs
--cve CVE-...              restrict to one or more CVEs
--jobs N                   concurrent testcase workers
--dry-run                  write prompts/schema without calling the model
--resume                   skip completed entries in the output JSON
--retry-errors             rerun error entries together with --resume
--retry-inconclusive       rerun inconclusive entries together with --resume
--debug-dir PATH           merge matching separated debug files
--codex-bin PATH           use a specific Codex executable
--codex-json-events        retain detailed Codex event and timing records
```

Keep the same `--output` and `--raw-dir` when resuming. A rerun is safe because
each testcase has its own raw files and the Ghidra cache is hash-addressed.

## Outputs and metrics

The output JSON is a CVE-to-binary status map. The raw directory normally
contains:

```text
batch_manifest.json
single_cve_schema.json
<case>.prompt.txt
<case>.stdout
<case>.stderr
<case>.last.json
<case>.timing.json
<case>.timing.md
<case>.anonymized_targets.json
<run_id>.ghidra.json
<run_id>.ghidra_queries.jsonl
```

The manifest records the normalized invocation, model profile, metadata and
Ghidra mode, cache reuse/failure counts, and tool-call counts. API keys and
ground truth are not recorded in prompts or manifests.

The metrics sidecar reports `TP`, `TN`, `FP`, `FN`, `inconclusive`, `error`,
`not_found`, `A`, `P`, `R`, `F1`, and `DSR`. Ground-truth `vuln` expects
`absent`, `patch` expects `present`, and `not_affected` expects
`not_affected`. A high F1 with many errors or inconclusive cases is not a
successful complete run; inspect the raw counts and testcase statuses.

## Development and troubleshooting

Run lightweight checks from the repository root:

```bash
python3 -m json.tool model_config.json.template >/dev/null
python3 -m compileall -q codex_batch
git diff --check
pytest -q                       # if the test dependencies are installed
```

Common failures:

- `model_config.json not found`: copy `model_config.json.template`, then set
  the API-key environment variable for the chosen profile.
- `prompt template does not exist`: use an absolute prompt path or run from
  the repository root.
- Many `error` statuses: inspect one `.stderr` and `.last.json`, then check
  the provider endpoint, credentials, model profile, and timeout.
- Ghidra `auto` failures: verify the install directory and optional Python
  packages; the run should continue with objdump-only evidence.
- Ghidra `on` failures: fix the dependency/cache issue or use `auto` if
  degraded analysis is acceptable.
- Missing binaries: compare testset names with the compiler/optimization
  suffix and check the target-resolution order above.
- Interrupted runs: resume with the original output/raw paths and add
  `--retry-errors` when appropriate.

## Security and reproducibility boundaries

The model receives only the selected anonymous binary, prompt metadata, and
bounded static observations. It must not access source trees, diff files,
exports, ground-truth files, or arbitrary filesystem paths. Ghidra tools are
read-only queries tied to the current testcase and cannot execute the target.

For reproducible experiments, record the Git commit, dataset export names,
compiler/optimization suffix, model profile, reasoning effort, Ghidra mode,
Ghidra installation version, and the raw output directory. Keep local model
configuration and credentials outside version control.
