# claudeagent

`claudeagent` is a model-driven harness for binary patch-presence testing. Given complete, answer-scrubbed CVE metadata and one stripped target binary, the investigator uses bounded local `binutils` observations to return `present`, `absent`, `not_affected`, or `inconclusive`.

## Non-negotiable constraints

- Metadata is investigation guidance, never verdict evidence.
- The model sees only supplied metadata, `/workspace/binary`, and controlled inspection output. Do not expose source repositories, debug artifacts, DWARF data, sibling binaries, paths, or ground truth.
- `run_python` is the only inspection surface. Every determinate verdict must cite earlier returned, summarized evidence IDs. Each summary preserves model-selected excerpt lines and address locators for independent verification; the Host validates excerpt structure but not textual correspondence with the observation.
- The Host validates tool schemas, ledger provenance, evidence polarity, and final artifacts. Failures repair in-band instead of crashing.

## Architecture

- `agent_loop.py`: bounded model/tool loop and finalization phases.
- `run_python_tool.py`, `sandbox.py`: isolated binary inspection.
- `runtime.py`, `observations.py`, `evidence_summary.py`: immutable observations plus revisable Agent claims.
- `finalize.py`: direct evidence-cited verdict validation and `final_result.v6` artifacts.
- `batch.py`: testset selection, groundtruth lookup, resume protection using the metadata SHA-256, and aggregate metrics.

Run commands from `/home/zhangxb/ClawSpace/codex`. Use `--dry-run` before provider-backed runs when changing prompts, schemas, or model configuration.
