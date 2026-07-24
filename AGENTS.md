# Repository Guidelines

## Project Structure & Module Organization

Run this flat Python package from its parent (`/home/zhangxb/ClawSpace/codex`) so `claudeagent` imports resolve. `agent_loop.py` runs one CVE/binary investigation; `batch.py` runs a test set. Evidence state and artifacts live in `runtime.py`, `observations.py`, `evidence_summary.py`, and `finalize.py`. Tool contracts are in `tools.json`, `prompts/`, and `schemas/`. Put regression tests in `tests/`; never commit ignored `runs/` output.

## Build, Test, and Development Commands

There is no build system or committed dependency manifest. From the package parent:

```sh
python3 -m claudeagent.agent_loop --cve-id CVE-2013-0249 \
  --metadata-json <metadata.json> --binary <binary> \
  --output-dir /tmp/claudeagent_case --dry-run
python3 -m claudeagent.batch --testset <testset.json> \
  --groundtruth <groundtruth.json> --out-root /tmp/claudeagent_batch --dry-run
```

`--dry-run` validates inputs, renders the prompt, and checks the sandbox without a model request. Run offline checks with:

```sh
for test in test_finalize test_model_config test_responses_loop test_sandbox \
  test_waf test_prompting test_batch test_evidence_summary; do
  python3 -m claudeagent.tests.$test || exit 1
done
```

## Coding Style & Testing

Use four-space indentation, module docstrings, double-quoted strings, and modern type hints. Use `snake_case` for functions/variables and `PascalCase` for classes. Tests are standalone `_run()` scripts named `tests/test_<area>.py`; add a focused case for each behavior or safety change. No formatter, linter, or coverage threshold is configured.

## Harness Safety Rules

Read `CLAUDE.md` before changing model inputs, evidence flow, or finalization. The model may inspect only `/workspace/binary`; never expose source, DWARF/debug data, sibling artifacts, or local repositories. Evidence starts pending and must be summarized before citation. Determinate verdicts need summarized tool-emitted evidence; invalid submissions must return a repair response rather than aborting the run.

## Commits and Pull Requests

Use imperative, sentence-case commit subjects, for example `Simplify evidence finalization`. Keep commits scoped. PRs should summarize behavior and safety impact, link issues when available, and state the exact test commands run.
