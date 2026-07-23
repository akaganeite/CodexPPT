# Repository Guidelines

## Project Structure & Module Organization

This is a flat Python package. Run module commands from the package parent (`/home/zhangxb/ClawSpace/codex`) so `claudeagent` imports resolve. The main entry points are `agent_loop.py` for one binary/CVE case and `batch.py` for curl test-set runs. Model configuration lives in `model_config.py` and `model_config.json`; API, sandbox, and tool execution live in `responses_client.py`, `sandbox.py`, `run_python_tool.py`, and `binary_workspace.py`. Patch metadata compilation, grounding validation, and caching live in `patchspec/`. Keep evidence and result handling in `runtime.py`, `observations.py`, and `finalize.py`. Supporting contracts are in `prompts/`, `tools.json`, and `schemas/`. Put regression tests in `tests/`; `runs/` is ignored generated output and must not be committed.

## Build, Test, and Development Commands

There is no build system or committed dependency manifest. From the package parent, use:

```sh
python3 -m claudeagent.agent_loop --cve-id CVE-2013-0249 \
  --metadata-json <metadata.json> --binary <binary> \
  --output-dir /tmp/claudeagent_case --dry-run
python3 -m claudeagent.batch --out-root /tmp/claudeagent_batch --dry-run
python3 -m claudeagent.patchspec --metadata-json <metadata.json> \
  --cve-id CVE-2013-1944 --output /tmp/patch_spec.json --dry-run
```

`--dry-run` validates inputs and the harness path without making a model request. The PatchSpec command produces an in-memory deterministic preview in dry-run mode. Run all offline checks with:

```sh
for test in test_finalize test_model_config test_responses_loop test_sandbox test_waf \
  test_patchspec test_prompting test_batch_patchspec test_supports test_decision \
  test_evidence_verifier; do
  python3 -m claudeagent.tests.$test || exit 1
done
```

## Coding Style & Testing

Use four-space indentation, module docstrings, double-quoted strings, and modern type hints. Name functions and variables in `snake_case`, classes in `PascalCase`, and keep modules focused on one stage of the loop. No formatter, linter, or coverage threshold is configured; match nearby code. Tests are standalone `_run()` scripts with local assertions, named `tests/test_<area>.py`. Add a focused test for every behavior or safety change. The sandbox test requires a usable `bwrap` installation.

## Harness Safety Rules

Read `CLAUDE.md` before changing model inputs, evidence flow, or finalization. Never expose source, DWARF/debug data, sibling artifacts, or local repositories to the model, transcript, or evidence ledger. Determinate verdicts must cite tool-emitted evidence IDs, and invalid finalization payloads must return a repair response rather than abort the run.

## Commits and Pull Requests

Use imperative, sentence-case commit subjects, for example `Add sandbox preflight coverage`. In the body, explain the rationale and list affected modules when useful. Keep changes scoped. PRs should summarize behavior and safety impact, link related issues when available, and state the exact test commands run; include artifacts or screenshots only when they clarify changed output.
