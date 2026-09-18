# Ubuntu Deployed Balanced Dataset Builder

`deployed/` consumes `<project>_metadata.json` from a completed `base/` dataset
and builds balanced Ubuntu prebuilt-binary patch-presence testsets with one to
three source versions per label. It does not
modify `base/`, rediscover functions, or compile project source code.

## Workflow

1. `candidate_discovery/`: parse Ubuntu Security CVE JSON and collect exact
   Launchpad source/package publication candidates.
2. `testset_selection/`: precheck a time-spread Launchpad source-version pool,
   then use Codex exec to assign source labels before balanced near/mid/far
   selection of up to three versions per label.
3. `package_acquisition/`: rank the closed package set, download deb/ddeb pairs,
   verify Build-IDs, unstrip ELFs, and validate symbol/DWARF function evidence.
4. `dataset_export/`: assemble trace records, artifacts, reports, and final
   testset files.

## Commands

Run the full workflow in one command:

```bash
python3 deployed/dataset_builder.py run \
  -p openssl \
  --metadata ~/extdisk/dataset4ppt/openssl \
  --output deployed/runs/openssl-26 \
  --arch arm64 \
  --max-per-label 1 \
  --resume
```

`--max-per-label 1` constrains source selection, package search, validation,
and the public variant export to exactly one vulnerable and one patched source
version per retained CVE. The default remains up to three per label. `--arch
arm64` selects Ubuntu AArch64 packages. Because `deployed/` consumes Ubuntu
prebuilt packages, their compiler and optimization level come from Ubuntu's
package build and cannot be forced to a local `gcc -O2` setting.
Runtime/debug extraction and artifact work directories include the Ubuntu
architecture, so amd64 and arm64 package caches cannot be reused across variants.

When `--cve`, `--cve-file`, or `--cve-json` is omitted, `run` uses the CVEs in
the base dataset's `exports/testset.json`. It downloads Ubuntu Security JSONs
into `<output>/deployed/input/ubuntu-cves/`, writes source-level selection under
`<output>/deployed/selection/`, and writes final binaries directly under the
base-shaped `<output>/binaries/` and `<output>/exports/` roots. After two
successful validation passes, `run` deletes source extraction, artifact, and
deb/ddeb download caches. `--skip-validation` retains those work caches.

With `--resume`, completion is checked per CVE from the final variant exports,
the detailed trace, `resolved_3v3.json`, and artifact state, including the
existence of both stripped and debug files. Complete CVEs skip Ubuntu lookup,
source review, package ranking, and downloads. Only incomplete or newly added
CVEs enter the workflow. Successful new results are merged into the retained
state and cumulative exports before binary pruning, so a small scoped update
cannot remove previously completed CVEs or binaries. `--refresh` and
`--refresh-package-ranking` explicitly opt the requested CVEs back into work.
If a finalized output directory was moved, `run` rebases retained absolute
paths from its manifest to the current `--output` before checking completion.
When package validation exhausts the reviewed pool, `run` performs up to two
source fallback rounds by default. Each round selects binary-ready reserves
from the failed near/mid/far strata, asks Codex to review only those new source
versions, reranks the enlarged closed package set, and retries unresolved CVEs.
Use `--max-source-fallback-rounds 0` to disable this behavior.

Migrate an existing legacy `<output>/dataset/` run to the compact layout:

```bash
python3 deployed/dataset_builder.py finalize \
  -p openssl \
  --metadata ~/extdisk/dataset4ppt/openssl \
  --output deployed/runs/openssl-27 \
  --arch x86
```

Repair deployed metadata after moving a dataset or recovering it from an older
base export:

```bash
PYTHONPATH=. python3 -m deployed.candidate_discovery.metadata_backfill \
  --project openssl \
  --output ~/extdisk/dataset4ppt/deployed/openssl \
  --repo ~/extrepo/CVE-Dataset-target/openssl \
  --base-root ~/extdisk/dataset4ppt
```

The backfill is deterministic: it retains only CVEs present in the final
deployed groundtruth, relocates local diff paths, records diff hunks, and fills
missing function source files from the fix commit and its parent. It does not
download packages, invoke an LLM, or modify binaries, testsets, groundtruth,
or package-selection state. Its per-project audit is written to
`deployed/audit/metadata_backfill.json`. Use `--dry-run` to inspect the result
without rewriting the metadata export.

Populate behavior metadata for the CVEs actually retained by deployed binaries:

```bash
PYTHONPATH=. python3 -m deployed.candidate_discovery.behavior_backfill \
  --project openssl \
  --output ~/extdisk/dataset4ppt/deployed/openssl \
  --repo ~/extrepo/CVE-Dataset-target/openssl \
  --base-root ~/extdisk/dataset4ppt
```

The behavior backfill first reuses complete base/deployed behavior entries, then
uses local git and the deployed metadata to prepare reduced function context for
only missing CVEs. DeepSeek is called only for those missing entries. The final
`exports/<project>_behavior.json` is restricted to the deployed groundtruth CVE
set and includes five semantic anchors per function plus deterministic patch
commit/source-location data. Its audit is
`deployed/audit/behavior_backfill.json`; `--source-only` prepares the local
source analysis without calling DeepSeek.

Generate Ubuntu release-level groundtruth:

```bash
python3 deployed/dataset_builder.py groundtruth \
  --cve-json /path/CVE-2023-46218.json \
  --output deployed/runs/curl-groundtruth
```

Inspect exact source history as a standalone intermediate step:

```bash
python3 deployed/dataset_builder.py source-groundtruth \
  --cve-json /path/CVE-2023-46218.json \
  --output deployed/runs/curl-source-groundtruth
```

Select a balanced candidate pool. The command name is retained for compatibility:

```bash
python3 deployed/dataset_builder.py select-3v3 \
  -p curl \
  --metadata ~/extdisk/dataset4ppt/curl \
  --cve-json /path/CVE-2023-46218.json \
  --output deployed/runs/curl-3v3 \
  --arch x86 \
  --max-candidates-per-side 8 \
  --max-per-label 1 \
  --max-selection-minutes 20 \
  --selection-jobs 1
```

`--max-candidates-per-side` bounds the initial Codex-reviewed versions per
temporal side. The selector cheaply prechecks up to three times that number,
spread across the complete time range, and retains the remaining binary-ready
rows as fallback reserves. `--selection-jobs` defaults to `1`. A value of `2`
can help when the Codex service has spare capacity; larger values may increase
queueing latency.

Resolve and build a final balanced set from one or more candidate-pool files:

```bash
python3 deployed/dataset_builder.py build \
  -p curl \
  --metadata ~/extdisk/dataset4ppt/curl \
  --selection-file deployed/runs/curl-3v3/exports/selected_3v3.json \
  --output deployed/runs/curl-ranked-build \
  --max-version-attempts 4 \
  --max-per-label 1 \
  --max-package-families 3 \
  --max-search-minutes 30 \
  --resume
```

`--selection-file` is repeatable. Selection targets the largest available
balanced set up to 3v3. For 3v3 it prefers one near, one middle, and one far
pair relative to each label's available timeline; 2v2 prefers near plus far, and 1v1
prefers near. A CVE with only one or two validated pairs is retained as 1v1 or
2v2. Build ranks version combinations and commits a CVE only after every
function succeeds for every selected version. Version attempts are ordered
from the largest stratified balanced set down to 1v1; with the default four
attempts, a failed 3v3 can therefore fall back to a viable alternative 3v3,
2v2, or 1v1. Defaults bound search to four version combinations, three package
families per function, and 30 minutes per CVE. Downloads use the remaining
selection/build budget rather than an unbounded network timeout. The standalone
`build` command searches only its supplied reviewed pool; adaptive source
expansion belongs to the full `run` orchestrator.

## DeepSeek Configuration

Settings live in `deployed/llm_config.json` and can be replaced with
`--llm-config`:

```json
{
  "base_url": "https://api.deepseek.com",
  "endpoint": "/chat/completions",
  "model": "deepseek-v4-pro",
  "api_key": "",
  "api_key_env": "DEEPSEEK_API_KEY"
}
```

Use either `api_key` or the configured environment variable. Do not commit a
populated key. Missing or failed API access preserves functionality through a
deterministic fallback ranking. Prompts and normalized results are cached under
`<output>/state/package_ranking/`.

## Important Outputs

For a verified full `run`, the public dataset surface follows the base layout:

```text
<output>/
├── binaries/target/<project>_stripped/
├── binaries/target/<project>_debug/
├── exports/testset.ubuntu-<arch>.json
├── exports/groundtruth.ubuntu-<arch>.json
├── exports/<project>_metadata.json
├── exports/<project>_reference.json
└── deployed/
    ├── input/                 Ubuntu Security input JSON
    ├── selection/exports/     candidate pools and balanced selection evidence
    ├── state/                 resume, ranking, and package-search state
    ├── trace/                 detailed evidence, package URLs, and reports
    ├── audit/validation.json  final integrity audit
    └── manifest.json          layout and provenance manifest
```

`testset.ubuntu-amd64.json` and `groundtruth.ubuntu-amd64.json` retain the
base `CVE` / `functions` / `binaries` and `vuln` / `patch` schemas. Their
logical binary names are `project-source_version-binary_name`, matching base
exports after its compiler/optimization suffix is removed. The corresponding
files in `<project>_stripped` and `<project>_debug` append `-deployed` (and
`.debug` for debug files), for example
`openssl-3.5.0-2ubuntu1-libcrypto.so.3-deployed`.

The completed run removes these rebuildable work caches:

- `<output>/deployed/selection/sources/`
- `<output>/artifacts/`
- `<output>/downloads/`

Any CVE without a usable Ubuntu Security JSON is recorded under
`<output>/deployed/input/ubuntu_json_excluded.json` and excluded from the run.
The first missing JSON receives a five-second service probe. If Ubuntu's JSON
service is unavailable, the rest of that run immediately switch to the
official `ubuntu-cve-tracker` active/retired entries instead of waiting once per
CVE. Tracker text is normalized into the existing internal JSON shape and is
used only as release-status input; Launchpad publication collection, candidate
selection, and package validation remain unchanged. HTTP errors, timeouts,
connection failures, and invalid inputs do not block usable CVEs.

Canonical source and package downloads bypass configured HTTP proxies by
default because local proxies commonly break Launchpad redirects or TLS. Set
`DEPLOYED_CANONICAL_DIRECT=0` to force the standard proxy environment instead.

Source downloads prefer the Ubuntu archive and security pools, then the Ubuntu
snapshot nearest the Launchpad publication date, before using old-releases and
the original Launchpad URL. This keeps superseded source revisions available
without waiting on a slow Launchpad redirect. Package downloads similarly
prefer Ubuntu archive, snapshot, and ddebs mirrors for the exact Launchpad
filename. Cached deb/ddeb files are reused only after response-length and full
Debian data archive validation, so interrupted downloads are discarded and
fetched again.

The direct `select-3v3` and `build` commands remain stage-level tools and keep
their intermediate layout until `finalize` is invoked. When the output
filesystem cannot create symbolic links, source extraction automatically uses
`/tmp/agentic-dataset-deployed-sources/`. It can be redirected with
`DEPLOYED_SOURCE_WORKDIR` and is removed after a successful full run.

Source-version order relative to Ubuntu's fixed version is only a temporal
candidate hint. Schema-constrained `codex exec` assigns the final vuln/patch
label from the source tree and may reclassify either side. At least two distinct
binary-available source versions are required before source review. Initial
review candidates are distributed across near/mid/far time strata rather than
being truncated to the versions nearest the fix. Unreviewed prechecked versions
remain in the selection trace and can be reviewed incrementally after package
fallback. If the
affected function was renamed or refactored, source review also records the
candidate version's exact semantic function name. Package validation uses that
version-specific name for symbol/DWARF lookup while final testset and
groundtruth exports retain the canonical base metadata function name. If the
exact fixed Launchpad publication is unavailable, the selector keeps the fixed
version as the version boundary and uses the matching Ubuntu Security Notice
date as the time anchor. If that date is also unavailable, it records and uses
the nearest actual source publication as an approximate time anchor. A CVE is
excluded only when no balanced 1v1 can be established after Codex review.
Prompts, JSONL events, and results are retained under
`deployed/selection/state/codex_source_review/`.

`--source-download-timeout` controls each source-publication download budget.
`--source-review-timeout` independently controls each Codex source review and
defaults to 300 seconds. `--max-selection-minutes` remains the optional total
per-CVE selection budget; set it to `0` to disable that outer deadline.

## Module Boundaries

- `candidate_discovery/`: Ubuntu JSON parsing, base metadata input, Launchpad
  source history, and source-level groundtruth.
- `testset_selection/`: package-availability checks, Codex source review, and
  balanced 1v1-to-3v3 selection policy. `temporal_sampling.py` owns the
  near/mid/far review batches; `balanced_policy.py` owns pair construction and
  version-combination ranking.
- `package_acquisition/`: DeepSeek ranking, package-family search, deb/ddeb
  materialization, Build-ID, ELF, symbol, and DWARF validation.
- `dataset_export/`: final trace, artifact, report, and testset exports.
- Top-level `config.py`, `models.py`, `io_utils.py`, `logging_utils.py`,
  `system_utils.py`, and `versions.py` are infrastructure shared by stages.

## Validation

```bash
PYTHONPATH=. python3 -m unittest discover -s deployed/tests -p 'test_*.py'
python3 -m py_compile deployed/*.py deployed/*/*.py
git diff --check -- deployed

PYTHONPATH=. python3 -m deployed.dataset_export.validator \
  -p curl \
  --dataset /path/to/curl-output \
  --variant ubuntu-amd64 \
  --output /path/to/curl-output/deployed/audit/validation.json
```
