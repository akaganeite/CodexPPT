# SQLite Database Architecture

The source-build workflow stores incremental state in `<output>/<project>.sqlite`.
Schema version `4` removes the legacy v1/v2 shadow tables, normalizes build
configuration and target mappings, records the target architecture in each build
variant, and stores affectedness reviews globally per testcase and architecture
instead of per compiler/optimization artifact.

## Connection guarantees

Every `ProjectDB` connection enables:

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
```

Opening an older database creates a consistent SQLite backup, runs the required
migrations transactionally, executes `PRAGMA foreign_key_check`, and sets
`PRAGMA user_version=4` only after migration succeeds. Migration details
and the backup path are recorded in `schema_migrations`.

Use the explicit migration command when upgrading existing outputs:

```bash
python3 base/dataset_builder.py migrate-db \
  --db <output>/<project>.sqlite
```

The command writes `<output>/<project>.migration.json` unless `--report` is
specified.

## Entity relationships

```text
cves
 ├─ fix_candidates ── source_functions
 ├─ reference_binaries ── build_variants
 ├─ testset_entries
 │   ├─ target_mappings ── target_artifacts ── build_variants
 │   └─ affectedness_reviews ── reviewed target_artifact (optional)
 └─ rca_statuses

releases ── testset_entries
releases ── target_artifacts

project
schema_migrations
stage_runs
```

## Tables

### `schema_migrations`

Records applied schema migrations and their audit details.

- Primary key: `version`
- Important fields: `name`, `status`, `detail_json`, `started_at`, `completed_at`
- `detail_json` includes migrated row counts, pruned stale mappings/reviews,
  normalized path counts, and the backup path.

### `project`

Key/value project metadata, including the last build configuration.

- Primary key: `key`
- `build_config` is historical configuration. Current CLI `--repo`, `--output`,
  compiler, and optimization arguments remain the runtime source of truth.

### `cves`

NVD CVE metadata and selection state.

- Primary key: `cve_id`
- Stores raw NVD JSON, summary, CWE, references, publication dates, selection,
  and metadata processing status.

### `fix_candidates`

Candidate and selected fix commits for each CVE.

- Primary key: `id`
- Unique key: `(cve_id, commit_hash)`
- Foreign key: `cve_id -> cves.cve_id`, delete cascade
- `diff_path` is stored relative to the project output when possible.

### `source_functions`

Functions and source files changed by a fix candidate.

- Primary key: `(cve_id, commit_hash, function)`
- Foreign key: `(cve_id, commit_hash) -> fix_candidates`, delete cascade
- `active=1` identifies the current source analysis result.

### `releases`

Project tag and release timeline.

- Primary key: `tag`
- Stores commit, date, raw version, and normalized version.

### `build_variants`

Canonical build configurations shared by reference and target artifacts.

- Primary key: `id`
- Unique key: `(architecture, compiler, opt, build_profile)`
- `architecture` is canonicalized to `x86_64` or `aarch64`.
- Examples: `x86_64/gcc/-O0/`, `x86_64/gcc/-O2/`,
  `aarch64/gcc/-O2/`

This table prevents architecture, compiler, and optimization strings from
drifting across reference and target artifact tables. Existing pre-v4 rows are
migrated to `x86_64`.

### `reference_binaries`

Vulnerable and patched reference binaries for one CVE and build variant.

- Primary key: `id`
- Unique key: `(cve_id, build_variant_id)`
- Foreign keys:
  - `cve_id -> cves.cve_id`, delete cascade
  - `build_variant_id -> build_variants.id`, delete restrict
- `vuln_path` and `patch_path` are output-relative when possible.

The former `reference_binaries`/`reference_binaries_v2` double-write is removed.

### `testset_entries`

The selected CVE label/tag/binary business entries.

- Primary key: `id`
- Unique key: `(cve_id, label, tag, binary_name)`
- Foreign keys:
  - `cve_id -> cves.cve_id`, delete cascade
  - `tag -> releases.tag`, delete restrict
- Labels normally include `vuln` and `patch`.

Deleting and replacing entries for one CVE automatically deletes dependent
mappings and reviews.

### `target_artifacts`

Physical target binaries built for a release and build variant. This is the
single source of truth for current binary and debug paths.

- Primary key: `id`
- Unique key: `(tag, binary_name, build_variant_id)`
- Foreign keys:
  - `tag -> releases.tag`, delete restrict
  - `build_variant_id -> build_variants.id`, delete restrict
- Path fields:
  - `path`: current stripped/raw target binary
  - `debug_path`: separated debug information
- Both paths are output-relative when possible.

`debug_split` updates only this table. It does not synchronize review or legacy
path copies.

### `target_mappings`

Maps a selected testset entry to a reusable target artifact.

- Primary key: `id`
- Unique key: `(testset_entry_id, artifact_id)`
- Foreign keys:
  - `testset_entry_id -> testset_entries.id`, delete cascade
  - `artifact_id -> target_artifacts.id`, delete restrict

CVE, label, tag, binary, compiler, optimization, and path are obtained through
joins rather than duplicated here.

### `affectedness_reviews`

Affectedness audit result for one testcase, review policy, and target
architecture. A testcase review is shared by every compiler/optimization
configuration within one architecture, but never across `x86_64` and `aarch64`.

- Primary key: `id`
- Unique key: `(testset_entry_id, policy, architecture)`
- `architecture` is canonicalized to `x86_64` or `aarch64`; legacy reviews are
  migrated to `x86_64`.
- Foreign keys:
  - `testset_entry_id -> testset_entries.id`, delete cascade
  - `reviewed_artifact_id -> target_artifacts.id`, delete set null
- Status values include `affected`, `not_affected`, `patch_evolution`,
  `backport_fix`, `missing_fix`, `wrong_binary`, `inconclusive`, and `failed`.
- `missing_functions_json` is review data, not part of the business key.
- `reviewed_artifact_id` records which first successful artifact was audited but
  does not participate in the unique key.
- Target paths are not stored; current paths are joined from `target_artifacts`.

This replaces both `not_affected_reports` and `not_affected_reviews`.

### `stage_runs`

Pipeline stage execution history.

- Primary key: `id`
- Index: `(stage, id DESC)`
- The latest record determines resume status.
- `record_stage` retains the most recent 50 rows per stage.

### `rca_statuses`

Current RCA state for each CVE and mode.

- Primary key: `(cve_id, mode)`
- Foreign key: `cve_id -> cves.cve_id`, delete cascade
- `artifact_path` is output-relative when possible.

## Removed legacy tables

Schema version 2 removed these runtime tables:

- `reference_binaries_v2`
- `target_binaries`
- `target_mappings_v2`
- `not_affected_reports`
- `not_affected_reviews`

Their useful data is migrated into the normalized tables. Mappings that no
longer have a matching current `testset_entries` row are stale incremental state
and are pruned. Reviews attached only to those stale mappings are pruned with
them. Schema version 3 then collapses reviews to `(testset_entry_id, policy)`.
Consistent historical statuses retain the newest row and its artifact; conflicting
statuses are omitted so the testcase becomes pending and is reviewed again on
the next successful build. Conflict keys and statuses are recorded in
`schema_migrations.detail_json`. Schema version 4 adds architecture to build
variants and review identities, assigning all historical rows to `x86_64`.

## Path semantics

Files managed under the project output are stored as relative paths. Public
`ProjectDB` query methods resolve them against the SQLite file's parent directory
before returning them to build stages.

```text
stored:   binaries/target/binutils_stripped/binutils-2.40-objdump-gcc-O2
runtime:  <current-output>/binaries/target/binutils_stripped/...
```

An AArch64 target uses an architecture-qualified build variant in its physical
name, for example `binutils-2.40-objdump-aarch64-gcc-O2`. AArch64 reference
binaries are stored below `binaries/reference/<project>/aarch64/`; x86-64 keeps
the historical reference directory unchanged.

Absolute paths outside the output, if any, are preserved. The current repository
path always comes from the current CLI `--repo` argument rather than historical
`project.build_config` data.

## Consistency checks

Run these checks after migration:

```sql
PRAGMA user_version;       -- must be 4
PRAGMA foreign_keys;       -- must be 1
PRAGMA integrity_check;    -- must return ok
PRAGMA foreign_key_check;  -- must return no rows
```

No duplicate affectedness business keys should exist:

```sql
SELECT testset_entry_id, policy, architecture, COUNT(*)
FROM affectedness_reviews
GROUP BY testset_entry_id, policy, architecture
HAVING COUNT(*) > 1;
```

No orphan mappings should exist:

```sql
SELECT m.id
FROM target_mappings m
LEFT JOIN testset_entries t ON t.id=m.testset_entry_id
LEFT JOIN target_artifacts a ON a.id=m.artifact_id
WHERE t.id IS NULL OR a.id IS NULL;
```
