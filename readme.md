# CODEX4PPT

`CODEX4PPT` is a batch runner for binary patch-presence detection. It
launches `codex exec` tasks over target binaries and asks an LLM agent to decide
whether the patch-relevant security behavior for each CVE/binary testcase is:

- `present`
- `absent`
- `not_affected`
- `inconclusive`
- `not_found`
- `error`

The repository code does not perform the binary reasoning directly. Its job is
to prepare the agent environment, pass patch-focused metadata into prompts,
invoke `codex exec`, capture raw logs, parse the model's JSON answer, merge
per-task results, and compute evaluation metrics.

## Repository Components

- `codex_patch_presence_batch.py`: main CLI entry point.
- `codex_batch/`: batch orchestration, target anonymization, prompt rendering,
  result parsing, model/profile handling, and metric computation.
- `codex_batch/ghidra_manager.py`: SHA-256 cache preparation, dependency
  checks, locking, and per-run Codex MCP isolation.
- `codex_batch/ghidra_mcp.py` and `codex_batch/ghidra_tools.py`: a local stdio
  MCP server exposing six bounded read-only Ghidra tools for one anonymous
  target binary.
- `prompts/`: prompt templates for different binary settings.
- `utils/safe_objdump.py`: bounded helper exposed to the agent for local binary
  inspection.
- `metadata/`: offline scripts for constructing patch-focused metadata used by
  detection prompts.
- `AGENTS.md`: operational handoff guide for running experiments on another
  machine.
- `CLAUDE.md`: implementation notes and developer-facing architecture details.

## Detection Contract

The prompt contract requires the agent to base decisions on local binary
evidence, not on release/version strings or source-file inspection. Ground truth
is used only by the wrapper after model execution to score results; it is not
made visible to the agent during detection.

## Optional native Ghidra tools

Install the pinned optional dependencies and make Ghidra available:

```bash
python3 -m pip install -r requirements-ghidra.txt
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.4.2_PUBLIC
```

The install directory is resolved in this order: `--ghidra-install-dir`,
`GHIDRA_INSTALL_DIR`, the known local Ghidra 11.4.2 installation, then
PyGhidra's own discovery. Four CLI flags control the integration:

```text
--ghidra off|auto|on
--ghidra-cache-dir PATH
--ghidra-install-dir PATH
--ghidra-timeout SECONDS
```

- `off` is the default and preserves the existing objdump-based workflow.
- `auto` tries Ghidra and falls back without the tools if preparation fails.
- `on` treats a preparation or MCP-start failure as an error for that testcase
  without stopping other testcases.

Ghidra analyzes the anonymous, optionally unstripped file prepared for the
individual `--binarywise` task. Cache entries live under
`~/.cache/straight_detect/ghidra/<sha256>/`; a per-hash lock prevents duplicate
or corrupt initialization under concurrent jobs. A cache-root JVM capacity
lock prevents memory spikes while preserving concurrent Codex tasks. Each
Codex process receives only the `straight_detect_ghidra` MCP server and these
tools:

```text
ghidra_locate_function
ghidra_function_summary
ghidra_cfg_slice
ghidra_path_probe
ghidra_call_args
ghidra_decompile_slice
```

The tools cannot accept a target path or arbitrary Ghidra script. Their output
is bounded and path-sanitized. Decompiler text is advisory; determinate results
must also use raw instructions, CFG, or P-code evidence. Because all six tools
are fixed-target and read-only, the injected server pre-approves them so a
non-interactive `codex exec` batch cannot cancel a tool call while waiting for
user approval.

Example stripped-binary run:

```bash
python3 codex_patch_presence_batch.py \
  --project-json /data/openssl/exports/openssl_behavior.json \
  --testset-json /data/openssl/exports/testset.json \
  --target-dir /data/openssl/binaries/target/openssl_stripped \
  --groundtruth-json /data/openssl/exports/groundtruth_with_not_affected.json \
  --compiler gcc \
  --opt O2 \
  --output /tmp/openssl_ghidra_results.json \
  --raw-dir /tmp/openssl_ghidra_raw \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --model-profile codex_default \
  --codex-json-events \
  --ghidra on \
  --jobs 1 \
  --limit 1 \
  --timeout 3600
```

Alongside the existing prompt, stdout/stderr, final-message, and timing files,
each testcase writes `<run_id>.ghidra.json` and
`<run_id>.ghidra_queries.jsonl`. `batch_manifest.json` records the selected
mode, versions, cache schema/provenance, ready/reused/failed counts, and tool
query counts. `--dry-run` performs only dependency/path/config preflight and
does not launch Ghidra analysis.

## Results

Current summarized experiment results are recorded in:

```text
results.md
```

That file is the place to look for reported metrics and run-summary tables.
