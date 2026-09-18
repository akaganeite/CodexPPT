# sqlite compile adapter

Adapter: `binarybuild/compile/sqlite.py`

Public APIs:
- `compile_commit(config, ref, stage, log, profile="static") -> BuildOutput`
- `choose_binary(worktree, functions, preferred="", profile="static") -> BinaryMatch | None`
- `find_binary_by_name(worktree, binary_name, profile="static") -> Path | None`
- `copy_binary(src, dest) -> None`
- `target_filename(project_or_config, version, binary_name, compiler="", opt="") -> str`

Architecture support:
- Explicitly supports `x86_64` and `aarch64` through `SUPPORTED_ARCHITECTURES`.
- Uses only `config.toolchain` commands for CC/CXX, AR/RANLIB/NM/OBJDUMP/OBJCOPY/STRIP/READELF, and propagates central compiler flags to compilation and linking.
- Every AArch64 configure attempt passes `--host=config.toolchain.configure_host`; native package discovery is disabled for cross builds.
- When the checked-out `configure` script supports `--disable-tcl`, AArch64 builds pass it to prevent cross configuration from loading the host `/usr/lib/tclConfig.sh`. Older releases that do not advertise the option are left unchanged.
- AArch64 candidates and both sides of every copy are checked with the marker-recorded central `readelf` and must report ELF Machine `AArch64`.
- Passing a `BuildConfig` to `target_filename` delegates to `config.target_binary_name`, preserving existing x86_64 names and the `aarch64` target prefix.

Build strategy:
- Resolve each ref and create a detached git worktree below `config.worktree_root`; never configure or compile in the source checkout.
- Include commit, profile, architecture-qualified build variant, and adapter version in the worktree name so incremental runs cannot reuse an incompatible build. Reuse also requires a matching full-toolchain marker and architecture-correct ELF.
- Configure in `.agentic-build-<profile>-<attempt>` directories. Try feature-enabled static configuration first, then progressively older-compatible configure forms.
- When an old release's bundled GNU `config.sub` predates the `aarch64` machine name, refresh only the detached worktree copy from the system GNU config helper before passing the central configure host.
- Generate `sqlite3.c` and `sqlite3.h`; generate `shell.c` when that target exists. Older releases use `src/shell.c` directly.
- Compile a dedicated unstripped `agentic-sqlite3` executable from the amalgamation with `-g3`, the requested optimization, `-fno-inline`, `-fno-omit-frame-pointer`, and FTS3/FTS4/RTREE/JSON1 enabled. This retains local symbols needed by source-function matching.
- The `explain-comments` reference profile additionally defines `SQLITE_ENABLE_EXPLAIN_COMMENTS`, retaining debug-only helpers such as `vdbeVComment` when a security patch modifies them.
- Explicit `debug`, `fts5`, and `session` profile tokens enable real `SQLITE_DEBUG`, `SQLITE_ENABLE_FTS5`, and `SQLITE_ENABLE_SESSION` plus `SQLITE_ENABLE_PREUPDATE_HOOK` code respectively. Flags apply to the full amalgamation and configure/make fallback, never to extracted-function or stub builds. Ordinary `static`/`shared` profiles are unchanged; debug symbols (`-g3`) alone do not imply `SQLITE_DEBUG`.
- Fall back to the release's `make sqlite3` target if the direct amalgamation link is unavailable.
- Successful builds write an adapter signature marker and may remove detailed logs according to `config.cleanup_build_logs`. Failed build logs are retained.

Binary selection:
- Prefer `agentic-sqlite3`, then configured-tree `sqlite3`, `.libs/sqlite3`, and unstripped `libsqlite3.so*` fallbacks.
- Normalize all candidates to the stable dataset binary name `sqlite3`.
- Use both regular and dynamic symbol tables through the marker-recorded `config.toolchain.nm`. Select a candidate containing all requested functions when possible, otherwise return the candidate with the fewest missing functions.

Expected coverage:
- SQLite source releases using the historical Autoconf build and the newer Autosetup build between at least the supplied 2015 and 2025 reference commits.
- Core SQL compiler functions, ALTER TABLE helpers, printf internals, and FTS3/FTS4 internal functions are retained in the dedicated amalgamation executable.
