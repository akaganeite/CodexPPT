# Agentic Dataset Builder

This directory keeps the new one-shot dataset build workflow. The intended
usage is:

- Python owns the deterministic batch workflow, database state, resume logic,
  deduplication, exports, and cleanup.
- Codex batch is invoked for agentic steps that need repository reasoning or
  build debugging, especially CVE-to-diff and reference/target compilation.
- Reusable project compile scripts live under `base/binarybuild/compile/` and
  are improved by Codex batch over time.

## Get Started

Before running a build, prepare these prerequisites:

- A local git clone of the target project, with enough history and tags for the
  CVEs you want to build.
- Python 3.10+ with the `packaging` module available. The rest of the builder
  uses the Python standard library.
- The Codex CLI available as `codex`, logged in, and allowed to run
  `codex exec`. Agentic stages use schema-constrained JSON output.
- Core command-line tools: `git`, `ctags`, `nm`, `readelf`, `objdump`,
  `objcopy`, `strip`, `file`, and common shell/build utilities.
- A C/C++ build toolchain matching the selected strategy, usually `gcc` or
  `clang`, plus `make`.
- For `--arch aarch64`, the GNU glibc cross toolchain and binutils. On Ubuntu,
  install `g++-aarch64-linux-gnu` (it supplies the required C++ driver and
  pulls in the matching GCC/binutils dependencies). AArch64 Clang additionally
  uses the local `clang`/`clang++` with the GNU cross toolchain under `/usr`.
- Project build helpers as needed by old releases, commonly `autoconf`,
  `automake`, `autoreconf`, `libtoolize`, `pkg-config`, `cmake`, and `ninja`.
- Network access for NVD/CVE metadata and CVE reference pages unless the
  required data is already cached in the output SQLite database.
- Optional: an NVD API key through `--nvd-api-key` or `NVD_NIST_API_KEY` to reduce
  metadata fetch throttling.

Recommended first run:

1. Pick a stable output directory and keep using it for incremental updates.
2. Start with `--latest 20` or a small `--cve-file` to let Codex create or
   improve the project compile adapter.
3. Re-run with `--resume` for incremental builds. Existing CVE metadata, fix
   commits, source analysis, reference binaries, target binaries, and exports
   are reused when they already satisfy the current request.
   See `base/DATABASE.md` for the SQLite schema, keys, migration behavior, and
   consistency checks.
4. Inspect `log/YY-MM-DD-HH-MM/run.log` for the compact command-line progress
   stream, and `log/YY-MM-DD-HH-MM/codex_runs/` for Codex prompts, event logs,
   and structured results.

## Usage

An authoritative testset/groundtruth manifest can drive an exact rebuild without
rerunning CVE metadata, CVE-to-diff, source analysis, or affectedness review. The
manifest is keyed by project and CVE, with `vuln`, `patch`, and `not_affected`
logical binary lists. The builder refreshes release tags, builds the requested
architecture-specific canonical `gcc -O0` references and requested target
variant, records the manifest labels,
splits debug information, exports, and verifies that the variant testset and
groundtruth exactly match the manifest, including CVE order and the order of
logical binaries within each label. Existing valid reference anchors are reused;
missing references are rebuilt, and the locked-manifest run fails instead of
silently leaving an incomplete reference set.

```bash
python3 base/dataset_builder.py build \
  -p curl \
  --repo /path/to/curl \
  --output /path/to/dataset4ppt/curl \
  --testset-manifest /path/to/cdx_baseline_120_cves.json \
  --compiler gcc \
  --opt=-O2 \
  --arch x86_64 \
  --metadata-mode skip \
  --resume
```

The `build` command supports:

- Building a dataset from a local project git repository into one output directory.
- Incremental resume with `--resume`, reusing existing metadata, diffs, source analysis, binaries, database rows, and exports when they are already complete.
- CVE selection by latest N CVEs, repeated `--cve`, or `--cve-file`.
- `--cve-file` input with exactly one CVE id per line and no extra metadata.
- CVE metadata from the NVD CVE 2.0 API.
- Local git repo and tag refresh before each run.
- Target compiler strategy selection through `--compiler` and `--opt`.
  Target architecture is selected by `--arch x86_64` (default) or
  `--arch aarch64` (`arm64` is accepted as an alias). Reference binaries are
  always built as `gcc -O0` anchors for the selected architecture.
- Release tag normalization through `base/config.json` `tag_rules`.
- Testset selection through `--testset-strategy` and `--testset-count`, defaulting
  to `chronical` and `3`.
- Testset vulnerable-side candidates are filtered by NVD affected versions when
  available. Project-matching `affected[].affectedData[].versions[]` entries
  take priority over broad CPE ranges; CPE is used only when no such entries are
  available. If affected candidates are fewer than the requested
  count, the builder logs a warning and keeps the smaller set instead of
  supplementing outside the affected range.
- Agentic CVE-to-diff resolution, reference binary build, target binary build,
  and affectedness review through Codex batch. The review covers every selected
  target candidate, independent of symbol presence. It receives CVE summary,
  NVD affected ranges, fix commit/parent, target tag/commit, fix diff and source
  functions, plus target ELF/debug-companion facts, dynamic dependencies, and
  the reusable compile adapter/spec. Codex may inspect the artifact with
  read-only binary tools; source history alone is insufficient for optional,
  platform-specific, or feature-gated paths. Symbol presence is not used as a
  pre-filter or a standalone verdict.
- Final target-binary post-processing that splits debug/symbol information into
  separate debug files, updates SQLite/export paths to stripped target binaries,
  and removes the redundant raw target directory after a successful split.
- Optional RCA metadata extraction through `--metadata-mode source` or
  `--metadata-mode behavior`. The source mode writes reduced source context and
  compact RCA input, plus a deterministic related-file allowlist. The behavior
  mode additionally calls DeepSeek and writes a behavior JSON export when
  `DEEPSEEK_API_KEY` is available. Behavior output includes root-cause analysis,
  patch intent, and per-function semantic anchors for locating patch-touched
  functions in optimized stripped binaries. The related-file allowlist is an
  independent audit artifact and is not added to the DeepSeek prompt. RCA resume
  state is tracked per CVE, so newly added CVEs or older entries missing source
  analysis, the allowlist, or behavior anchors still trigger the needed RCA work.
- Project-specific reusable compile adapters under `base/binarybuild/compile/`.
- Final exports for metadata, reference binaries, testset labels, and not-affected candidates.
- Deterministic RQ2/RQ3 experiment-subset selection from completed exports.
  It does not compile binaries or call Codex; it profiles existing diffs, source
  metadata, affectedness-review output, and target debug companions.

Build the latest 20 CVEs:

```bash
python3 base/dataset_builder.py build \
  -p openssl \
  --repo ~/extrepo/CVE-Dataset-target/openssl \
  --output ~/extdisk/dataset4ppt/openssl \
  --latest 20 \
  --compiler gcc \
  --opt=-O0 \
  --testset-strategy chronical \
  --testset-count 3 \
  --resume
```

Incrementally update from a CVE file:

```bash
python3 base/dataset_builder.py build \
  -p openssl \
  --repo ~/extrepo/CVE-Dataset-target/openssl \
  --output ~/extdisk/dataset4ppt/openssl \
  --cve-file opensslupdate \
  --compiler gcc \
  --opt=-O0 \
  --testset-strategy branch-aware \
  --testset-count 3 \
  --resume
```

Build an AArch64 GNU target variant:

```bash
python3 base/dataset_builder.py build \
  -p openssl \
  --repo ~/extrepo/CVE-Dataset-target/openssl \
  --output ~/extdisk/dataset4ppt/openssl \
  --latest 20 \
  --arch aarch64 \
  --compiler gcc \
  --opt=-O2 \
  --testset-strategy chronical \
  --testset-count 3 \
  --resume
```

### RQ2/RQ3 Experimental Selection

Create a 20-CVE PPT evaluation subset from an existing dataset without changing
its normal build exports:

```bash
python3 base/dataset_builder.py select-rq-testset \
  -p ffmpeg \
  --repo /media/zhangxb/A8DB-5090/repos/FFmpeg \
  --output /home/zhangxb/extdisk/dataset4ppt/ffmpeg \
  --count 20
```

Use `--variant gcc-O2` when the experiment must use one explicit target
configuration. The selector excludes CVEs whose affectedness audit records
`patch_evolution`, then deterministically maximizes coverage of the paper's
RQ2 factors (repair semantics/complexity, patch and function-size strata, CWE,
and available compiler variants) and its non-evolution RQ3 factors. A
conditional-compilation example is admitted only when a strict
`not_affected` review gives explicit target-binary feature/code-absence
evidence. Symbol duplication likewise requires `nm` confirmation in an actual
target debug companion. Categories unavailable in a project are reported in
the manifest rather than inferred or forced.

The command writes only `pretest.rq2-rq3.pick*.json`,
`groundtruth.rq2-rq3.pick*.json`, and `rq2-rq3_selection_manifest*.json` under
`exports/`; it leaves `testset.pick*.json` and normal groundtruth exports
unchanged. If an old pick endpoint was later relabeled `not_affected`, the
experimental export repairs that endpoint to a current valid vuln/patch target.

### Command Options

Top-level commands:

- `build`: run the full agentic dataset build pipeline.
- `select-rq-testset`: derive a deterministic RQ2/RQ3-stratified PPT subset
  from an already built dataset.
- `cleanup-worktrees`: remove build worktrees for an existing output directory.
- `cleanup-build-logs`: remove detailed configure/make logs for an existing output directory.

`build` options:

- `-p, --project`: project name used for output paths, database rows, and project-specific config lookup.
- `--repo`: local git repository path for the target project.
- `--output`: output directory. Reuse the same directory for incremental updates.
- `--db`: optional SQLite database path. Defaults to `<output>/<project>.sqlite`.
- `--vendor-product`: explicit `vendor:product` CPE identity for NVD affected-version matching. Defaults to `base/config.json` `vendor_map`.
- `--latest`: select the latest N CVEs from NVD for the project.
- `--cve`: select one CVE id. Repeat this option to build multiple specific CVEs.
- `--cve-file`: read CVE ids from a file, one CVE id per line.
- `--compiler`: compiler name used for target binaries. Default: `gcc`.
  Reference binaries are fixed to `gcc`.
- `--opt`: optimization flag used for target binaries. Default: `-O0`.
  Reference binaries are fixed to `-O0`.
- `--arch`: target architecture: `x86_64` (default) or `aarch64`; `arm64` is
  normalized to `aarch64`. AArch64 GCC uses `aarch64-linux-gnu-*`; AArch64
  Clang uses `--target=aarch64-linux-gnu --gcc-toolchain=/usr`.
- `--testset-strategy`: testset selection strategy. Supported values: `chronical`, `branch-aware`, `time-bucket`. Default: `chronical`.
- `--testset-count`: number of vuln and patch target releases to select per CVE. Default: `3`.
- `--batch-size`: maximum batch size for Codex-driven stages. Default: `10`. Not-affected review also caps this at `10` target binary groups per Codex exec.
- `--codex-model`: optional Codex model override. Empty means use the Codex CLI default.
- `--codex-sandbox`: sandbox mode for `codex exec`; one of `read-only`, `workspace-write`, or `danger-full-access`. Default: `danger-full-access`.
- `--github-token`: optional GitHub token for reference-page and repository API access. Defaults to `GITHUB_TOKEN`.
- `--nvd-api-key`: optional NVD API key. Defaults to `NVD_NIST_API_KEY`.
- `--metadata-mode`: optional richer metadata extraction mode. Supported values: `skip`, `source`, `behavior`. Default: `skip`.
- `--cleanup-worktrees`: cleanup policy for temporary build worktrees after compile stages. Supported values: `success`, `all`, `none`. Default: `success`.
- `--cleanup-build-logs`: cleanup policy for detailed configure/make logs after compile stages. Supported values: `success`, `all`, `none`. Default: `success`.
- `--resume`: enable incremental behavior and skip satisfied stages.

`select-rq-testset` options:

- `-p, --project`: project name used by the existing export files.
- `--repo`: local project git repository used to inspect fix snapshots.
- `--output`: existing dataset output directory.
- `--count`: maximum number of CVEs to select. Default: `20`.
- `--variant`: optional target export variant such as `gcc-O2`. Without it, the
  selector uses the canonical pick export, falling back to `gcc-O2` when a
  canonical pick is unavailable.

`cleanup-worktrees` options:

- `-p, --project`: project name.
- `--repo`: local git repository path.
- `--output`: existing output directory.
- `--db`: optional SQLite database path. Defaults to `<output>/<project>.sqlite`.
- `--dry-run`: list removable worktrees without deleting them.

`cleanup-build-logs` options:

- `--output`: existing output directory.
- `--stage`: optional stage filter, either `reference_build` or `target_build`.
- `--dry-run`: list removable build logs without deleting them.

Supported testset strategies:

- `chronical`: select the nearest stable releases before and after the patch
  commit date.
- `branch-aware`: prefer patch releases from distinct version branches and pick
  vulnerable releases from those same branches when available.
- `time-bucket`: spread selections across near, middle, and far release
  distances instead of taking only nearest releases.

The command runs these stages:

1. `CVEhunt`: CVE metadata update
2. `CVEhunt`: fix commit / diff discovery
3. `CVEhunt`: source analysis
4. `binarybuild`: reference binary build
5. `testset`: release tag timeline update
6. `testset`: testset selection
7. `binarybuild`: target binary build
8. `binarybuild`: Codex affectedness review for all selected target candidates
9. `binarybuild`: split target debug/symbol information and strip target binaries
10. `testset`: export

Outputs are written under the selected output directory:

- `*.sqlite`: build state and incremental database
- `Diff/<project>/diff_files/`: selected fix diffs
- `binaries/reference/<project>/`: x86-64 reference binaries with debug and symbol information kept intact
- `binaries/reference/<project>/aarch64/`: AArch64 reference binaries with debug and symbol information kept intact
- `binaries/target/<project>_stripped/`: final stripped target binaries
- `binaries/target/<project>_debug/`: separated target debug/symbol files
- `exports/`: metadata, reference, unlabeled testset, groundtruth labels, not-affected views, and not-affected candidates
- `log/YY-MM-DD-HH-MM/{trace,warn,error}/`: structured JSONL logs, using UTC+8 24-hour time
- `log/YY-MM-DD-HH-MM/codex_runs/`: prompts, structured results, and Codex JSON event logs
- `worktrees/<project>/`: temporary git worktrees used by compile scripts
- `exports/<project>_related_file_allowlist.json`: deterministic C/C header file
  allowlist for RCA source inspection

The build also prints compact progress lines to stderr by default, for example:

```text
[trace] pipeline: stage start stage_name=cve_metadata
[trace] cve_metadata: fetched NVD CVEs count=...
[warn] reference_build: reference build item failed item=...
[trace] pipeline: stage done stage_name=target_build
```

Set `AGENTIC_DATASET_CONSOLE=0` to keep the terminal quiet and write only log
files.

The same compact progress stream is also appended to:

```text
log/YY-MM-DD-HH-MM/run.log
```

Each `run.log` line includes a UTC+8 timestamp.

## Incremental Behavior

Use `--resume` for incremental runs. A stage is skipped only when the latest
recorded stage status is complete and the current database content is satisfied.
For example, reference build is rerun if selected fixes with source functions
outnumber successful `gcc -O0` reference records for the requested
architecture. Reference binaries are shared across target optimization runs
within one architecture; running `--opt=-O2` should reuse existing same-arch
reference records and only add `-O2` target artifacts.

For `--latest N --resume`, the builder always refreshes the local repository and
the NVD latest-N selection window first. It then bootstraps only CVEs newly in
that window, or resumes window CVEs whose base artifacts or current target
variant are incomplete. Previously selected CVEs remain in the SQLite/export
scope and are not recompiled merely because a newer latest-N request was made.

For explicit `--cve`/`--cve-file` resume requests, CVEs with a selected fix,
source functions, existing `gcc -O0` reference files, and selected testset rows
take the variant-only path: target build, affectedness review only when globally
missing, debug split, and variant export. CVEs missing any prerequisite take the
bootstrap path through metadata, CVE-to-diff, source analysis, reference build,
release/testset selection, target build, review, canonical export, and optional
RCA. Mixed requests run upstream work only for bootstrap CVEs.

RCA source completeness also requires a matching
`related_file_allowlist.v2` entry. Existing outputs created before this artifact
are automatically routed through the deterministic RCA source step on resume;
existing behavior entries remain reusable because the behavior generator runs
with its own resume mode. For a base-ready scoped request, this can run RCA
without rerunning CVE discovery or binary compilation.

Affectedness reviews are keyed by testcase, policy, and architecture, so
successful GCC/Clang artifacts reuse the same conclusion only within one
architecture. The first successful artifact is recorded as review provenance;
a later configuration cannot overwrite a valid review.

Target binaries are deduplicated before Codex batch by:

```text
(tag, version, binary_name, architecture, compiler, opt)
```

If a target ELF already exists at:

```text
<output>/binaries/target/<project>/<project>-<version>-<binary_name>-<compiler>-<opt>
<output>/binaries/target/<project>/<project>-<version>-<binary_name>-aarch64-<compiler>-<opt>
```

the builder reuses it, maps it back to all related CVE/testset entries, and does
not send that target task to Codex again.

After target compilation and Codex affectedness review, `debug_split` rewrites
successful target artifact paths to:

```text
<output>/binaries/target/<project>_stripped/<project>-<version>-<binary_name>-<compiler>-<opt>
<output>/binaries/target/<project>_debug/<project>-<version>-<binary_name>-<compiler>-<opt>.debug
<output>/binaries/target/<project>_stripped/<project>-<version>-<binary_name>-aarch64-<compiler>-<opt>
<output>/binaries/target/<project>_debug/<project>-<version>-<binary_name>-aarch64-<compiler>-<opt>.debug
```

Reference binaries stay under `binaries/reference/<project>/` for x86-64 or
`binaries/reference/<project>/aarch64/` for AArch64 and keep their debug/symbol
information, because they are the verification anchor. Reference selection
requires modified functions on both sides, added functions on the patch side,
and deleted functions on the vulnerable side. A candidate that still misses a
required function is rejected instead of being accepted as the nearest match.
Resume applies the same architecture and side-specific symbol validation, so an
existing pair with the wrong binary kind is rebuilt rather than accepted by
path existence alone.
Project adapters use component-specific reference profiles when a changed
function is behind an optional build feature, such as curl mbedTLS/PolarSSL,
FFmpeg CBS JPEG, or SQLite explain comments. Curl diffs under `src/` prefer the
curl tool executable over `libcurl`. Once all recorded target ELFs are split successfully, the raw
`binaries/target/<project>/` directory is removed. On later incremental runs,
new raw target binaries cause `debug_split` to run again.

## Cleanup Commands

Successful build worktrees and detailed configure/make logs are cleaned by default:

```bash
--cleanup-worktrees success
--cleanup-build-logs success
```

Manual cleanup for an existing output:

```bash
python3 base/dataset_builder.py cleanup-worktrees \
  -p openssl \
  --repo /path/to/openssl \
  --output /path/to/output

python3 base/dataset_builder.py cleanup-build-logs \
  --output /path/to/output
```

Dry-run cleanup:

```bash
python3 base/dataset_builder.py cleanup-worktrees \
  -p openssl \
  --repo ~/extrepo/CVE-Dataset-target/openssl \
  --output /home/zhangxb/patch/agentic_dataset/output/openssl_latest20 \
  --dry-run

python3 base/dataset_builder.py cleanup-build-logs \
  --output /home/zhangxb/patch/agentic_dataset/output/openssl_latest20 \
  --dry-run
```

## Compile Scripts

Project-specific reusable compile scripts live in:

```text
base/binarybuild/compile/<project>.py
base/binarybuild/compile/<project>.spec.md
```

Reference and target build stages launch Codex batch compilation. The batch is
preceded by local adapter attempts where supported. SQLite reference profiles
for CVE-2020-11656, CVE-2023-7104, and CVE-2025-7709 explicitly enable DEBUG,
Session (with preupdate hooks), and FTS5 respectively in the full source build.
These profiles do not change ordinary target builds and do not fall back to
feature-disabled reference profiles. The batch is
prompted to read the project spec first, then use the existing project compile
script. If the script is missing or fails on old releases, Codex should create
or repair that script, debug the batch, update the spec when behavior changes,
and leave the improved script for future incremental runs.

For an AArch64 request, an adapter without explicit AArch64 capability is
always sent to Codex for repair before local reuse. Codex receives the central
toolchain contract, must use its cross compiler/binutils/configure host without
native fallback, must validate copied ELF architecture, and must update the
matching `.spec.md` whenever it changes adapter behavior or capability.

Existing project adapters are:

```text
base/binarybuild/compile/openssl.py
base/binarybuild/compile/openssl.spec.md
base/binarybuild/compile/curl.py
base/binarybuild/compile/curl.spec.md
```

The compile script API expected by the builder is:

```python
compile_commit(config, ref, stage, log, profile="static")
choose_binary(worktree, functions, preferred="", profile="static")
find_binary_by_name(worktree, binary_name, profile="static")
copy_binary(src, dest)
target_filename(project, version, binary_name, compiler="", opt="")
```

## Output Files

The export stage writes:

- `exports/<project>_metadata.json`: CVE metadata and source-level changed functions.
- `exports/<project>_reference.json`: reference vuln/patch binary pairs.
- `exports/testset.json`: selected target binaries grouped by CVE, without vuln/patch labels.
- `exports/groundtruth.json`: authoritative mutually exclusive `vuln`, `patch`, and `not_affected` labels grouped by CVE.
- `exports/testset.<compiler>-<opt>.json`: cumulative build+split successes for one x86-64 target configuration.
- `exports/groundtruth.<compiler>-<opt>.json`: authoritative mutually exclusive labels for exactly the same x86-64 configuration-specific artifact set.
- `exports/testset.aarch64-<compiler>-<opt>.json` and `exports/groundtruth.aarch64-<compiler>-<opt>.json`: architecture-isolated AArch64 views; the actual suffix is `aarch64-gcc-O2` or `aarch64-clang-O2`.
- `exports/testset.pick.<compiler>-<opt>.json`: one earliest original vuln-side and one latest original patch-side binary per CVE, selected only from the same build+split-success artifact set. Pair it with a suffixed groundtruth export.
- `exports/pretest.rq2-rq3.pick[.<compiler>-<opt>].json`: a separate
  deterministic 20-CVE RQ2/RQ3 experiment subset. Each selected CVE retains a
  valid vuln/patch pair; a strictly evidenced conditional-compilation case also
  carries one `not_affected` target binary.
- `exports/groundtruth.rq2-rq3.pick[.<compiler>-<opt>].json`: tri-state labels
  for exactly the matching RQ2/RQ3 experimental testset.
- `exports/rq2-rq3_selection_manifest[.<compiler>-<opt>].json`: selection
  inputs, feature profiles, coverage, deterministic scores, thresholds, and
  exclusions including `patch_evolution`.
- `exports/groundtruth_with_not_affected.<compiler>-<opt>.json`: compatibility alias of the configuration-specific tri-state groundtruth.
- `exports/not_affected.<compiler>-<opt>.json`: concise configuration-specific not-affected view. Matching `not_affected_candidates.<compiler>-<opt>.json` and `affectedness_audit_summary.<compiler>-<opt>.json` contain the review audit.
- `exports/groundtruth_with_not_affected.json`: compatibility alias of the canonical tri-state groundtruth. A binary moved to `not_affected` is removed from `vuln`/`patch`.
- `exports/not_affected.json`: concise reviewed not-affected binaries grouped by CVE, without reasons or evidence.
- `exports/not_affected_candidates.json`: all selected target candidates with Codex affectedness review results when available.
- `exports/affectedness_audit_summary.json`: count of affectedness review statuses such as `affected`, `not_affected`, `patch_evolution`, `backport_fix`, `missing_fix`, `wrong_binary`, `inconclusive`, and `failed`.
- `RCA/<project>.json`: project-level CVE metadata adapted from the base SQLite/export state for RCA source analysis.
- `RCA/<project>_project_source_analysis.full.json`: full RCA source analysis with reduced source context and debug details.
- `RCA/<project>_project_source_analysis.min.json`: compact RCA source analysis for behavior prompting.
- `exports/<project>_related_file_allowlist.json`: cumulative
  `related_file_allowlist.v2` audit output. Each CVE retains only its fix/parent
  commits, patch functions, patched `.c`/`.h` seed files, and resolved related
  files grouped by `functions`, `types`, and `macros`. The default 24-file cap
  still applies and `truncated` signals a capped result. Callers, include
  closure, build files, file contents, scores, unresolved symbols, and LLM
  generated context are excluded.
- `exports/<project>_behavior.json`: DeepSeek behavior/root-cause metadata, written when `--metadata-mode behavior` is used. Each CVE contains `function_anchors`, keyed by patch-touched function name, with up to five ranked semantic anchors for optimized stripped-binary function location. It also contains deterministic `patch_source` data: the canonical fix commit plus a non-deduplicated-by-name `locations` list of repo-relative files, post-patch function line ranges, and old/new changed line numbers.
- SQLite `rca_statuses`: per-CVE RCA status for `source` and `behavior` modes, used by `--resume` to rerun RCA only for missing or failed CVEs.

Not-affected reports are derived from the affectedness audit. Only strict
`not_affected` results are merged into `groundtruth_with_not_affected.json`;
`patch_evolution` and `backport_fix` keep the selected patch label instead of
being exported as not affected.

The current `affectedness-audit-v2` policy sends every pending selected target
to artifact-aware Codex review. During incremental migration, exports prefer a
v2 result and fall back to an existing v1 result only when that testcase has
not yet been reviewed under v2; pending detection itself never treats v1 as a
v2 result.

Variant-only resume runs update only the suffixed cumulative files. They do not
rewrite canonical metadata, reference, testset, groundtruth, not-affected, or
RCA exports. When bootstrap CVEs exist, canonical exports are regenerated from
the full database scope rather than the command's smaller CVE scope. Always use
testset and groundtruth files with the same `<compiler>-<opt>` suffix. Variant
export validates that every testset and pick binary has exactly one tri-state
label, so an unavailable artifact cannot silently become an unknown case.
When testset selection keeps the same `(CVE, label, tag, binary)` entry, its
SQLite ID, target mapping, and affectedness review are retained. Variant export
also deterministically reattaches an existing artifact only when its tag,
binary, compiler, optimization, and expected filename all match; this repairs
older databases without recompiling or rerunning Codex.

AArch64 exports are architecture-scoped: target variants use suffixes such as
`aarch64-gcc-O2`, for example `testset.aarch64-gcc-O2.json` and
`groundtruth.aarch64-gcc-O2.json`. ARM never rewrites unsuffixed canonical x86
testset/groundtruth/not-affected exports. Its source metadata and references
are written as `<project>_metadata.aarch64.json` and
`<project>_reference.aarch64.json`.

## Directory Layout

The stage code is split into three main directories:

- `base/CVEhunt/`: CVE metadata update, fix commit / diff discovery, and source analysis.
- `base/binarybuild/`: reference binary build, target binary build, compile-script management, and build cleanup.
- `base/testset/`: release tag timeline update, testset selection, and final exports.
- `base/RCA/`: local RCA source-analysis and behavior-metadata scripts copied into this repository; the base workflow does not call scripts from external workspaces.

Shared orchestration and infrastructure stays in:

- `base/builder/`: CLI, config, SQLite state, logging, and preprocessing.
- `base/utils/`: small shared helpers for command execution, Codex exec, paths, and file IO.
- `base/RCA/`: RCA project JSON adapter, reduced source-context extraction, and DeepSeek behavior metadata generation.

## Python Files

Top-level files:

- `base/dataset_builder.py`: CLI entrypoint; delegates to `builder.cli.main()`.
- `base/config.json`: project defaults, vendor/product mapping, legacy compile hints, tag rules, and testset strategy.

`base/CVEhunt/`:

- `base/CVEhunt/__init__.py`: package marker for CVE hunting stages.
- `base/CVEhunt/cve2diff_codex.py`: fetches CVE reference snapshots, prompts Codex to find the canonical fix commit, writes diff files, and stores selected fix candidates.
- `base/CVEhunt/cve_metadata.py`: fetches NVD CVE metadata and selects CVEs by `--latest`, repeated `--cve`, or `--cve-file`.
- `base/CVEhunt/source_analyzer.py`: git diff and ctags based C/C++ changed-function analyzer; also runs source analysis for selected fix commits and records changed functions.

`base/RCA/`:

- `base/RCA/__init__.py`: package marker for RCA stages.
- `base/RCA/behavior_stage.py`: converts current base SQLite/export state into RCA project JSON, runs local RCA source analysis, and optionally generates behavior JSON.
- `base/RCA/project_source_analysis.py`: local copy of the reduced source-context and source-sink analysis script.
- `base/RCA/patch_source.py`: deterministically merges selected fix commit and per-function source coordinates into behavior JSON after model analysis.
- `base/RCA/related_file_allowlist.py`: derives the cumulative C/C header related-file allowlist from each fix diff using deterministic direct callee, type, and macro definition lookup.
- `base/RCA/generate_behavior_analysis_deepseek.py`: local copy of the DeepSeek behavior/root-cause metadata generator.

`base/binarybuild/`:

- `base/binarybuild/__init__.py`: package marker for binary build stages.
- `base/binarybuild/build_log_cleanup.py`: lists and removes detailed configure/make logs under `log/YY-MM-DD-HH-MM/trace/*_builds`.
- `base/binarybuild/compile_scripts.py`: locates, loads, creates, and repairs reusable project compile scripts via Codex batch.
- `base/binarybuild/debug_split.py`: splits target ELF debug/symbol information into `<project>_debug`, writes stripped final target ELFs into `<project>_stripped`, updates SQLite paths, and removes the redundant raw target directory after successful splitting.
- `base/binarybuild/reference_build.py`: builds reference vuln/patch binary pairs through Codex batch, using the project compile script when available.
- `base/binarybuild/target_build.py`: builds selected target binaries through Codex batch, deduplicates by `(tag, version, binary_name, architecture, compiler, opt)`, validates ELF Machine, reuses existing ELFs, and maps binaries back to CVEs.
- `base/binarybuild/affectedness_evidence.py`: extracts compact, non-decisive ELF architecture, dependency, debug-companion, artifact-record, and compile-adapter facts for affectedness review.
- `base/binarybuild/not_affected_review.py`: reviews every selected target candidate directly through the artifact-aware Codex affectedness audit. It permits read-only target/debug inspection and records the review protocol and evidence provenance in SQLite.
- `base/binarybuild/worktree_cleanup.py`: removes temporary git worktrees safely through `git worktree remove --force`, with filesystem fallback.
- `base/binarybuild/compile/__init__.py`: package marker for reusable project compile scripts.
- `base/binarybuild/compile/openssl.py`: reusable OpenSSL compile adapter used by reference and target build stages.
- `base/binarybuild/compile/openssl.spec.md`: AI-friendly OpenSSL adapter map with overall behavior and per-function input/output/purpose.
- `base/binarybuild/compile/curl.py`: reusable curl compile adapter used by reference and target build stages.
- `base/binarybuild/compile/curl.spec.md`: AI-friendly curl adapter map with overall behavior, profile semantics, and per-function input/output/purpose.

`base/testset/`:

- `base/testset/__init__.py`: package marker for testset stages.
- `base/testset/export_stage.py`: writes final metadata, reference, testset, and not-affected JSON exports.
- `base/testset/rq_selection.py`: profiles existing source/diff/review/debug
  evidence and exports a deterministic RQ2/RQ3 PPT experiment subset without
  altering the regular dataset exports.
- `base/testset/releases_stage.py`: parses git tags into release/version rows for testset selection using `base/config.json` `tag_rules`.
- `base/testset/testset_stage.py`: selects testset tags around each reference patch using CLI strategy parameters; currently supports `chronical`, `branch-aware`, and `time-bucket`, and ignores prerelease tags.

`base/CVEhunt/` shared helpers:

- `base/CVEhunt/nvd_constraints.py`: canonical NVD affected-version parsing shared by testset selection and affectedness review prompts; it prefers project-matching exact `affectedData` versions and falls back to CPE ranges.

`base/builder/`:

- `base/builder/__init__.py`: package marker for dataset build orchestration.
- `base/builder/cli.py`: defines CLI commands, parses arguments, builds `BuildConfig`, and runs stages in order.
- `base/builder/config.py`: `BuildConfig` dataclass and derived output paths.
- `base/builder/architecture.py`: immutable x86-64/AArch64 toolchain contracts,
  preflight checks, architecture normalization, and deterministic ELF Machine
  validation.
- `base/builder/db.py`: core SQLite connection and persistence helpers for CVEs, fixes, functions, references, releases, testsets, targets, affectedness reviews, and RCA state.
- `base/builder/db_resume.py`: content-based resume/readiness checks, stage history, CVE bootstrap classification, and variant split satisfaction.
- `base/builder/db_schema.py`: schema versioning and transactional migration
  from legacy storage plus v3-to-v4 architecture-isolated build/review rows.
- `base/builder/logging.py`: stage logger that writes JSONL records split into per-run `log/YY-MM-DD-HH-MM/{trace,warn,error}` directories.
- `base/builder/preprocess.py`: writes build configuration to SQLite and updates the local git repo with `git fetch --all --tags --prune`.

`base/utils/`:

- `base/utils/__init__.py`: package marker for shared helpers.
- `base/utils/codex_exec.py`: builds and runs `codex exec` commands with schema-constrained JSON output.
- `base/utils/command.py`: runs subprocess commands into dedicated log files and returns structured command results.
- `base/utils/io.py`: JSON/text read-write helpers, UTC timestamps, JSONL event append, and text tailing.
- `base/utils/paths.py`: shared path constants for the `base` directory and default schema.

Schema files:

- `base/schemas/compile_script_result.schema.json`: required JSON shape for Codex compile-script create/repair tasks.
- `base/schemas/cve2diff_result.schema.json`: required JSON shape for Codex CVE-to-diff resolution.
- `base/schemas/reference_build_result.schema.json`: required JSON shape for Codex reference build batches.
- `base/schemas/target_build_result.schema.json`: required JSON shape for Codex target build batches.
