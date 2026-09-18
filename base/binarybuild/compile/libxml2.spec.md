# libxml2 compile adapter

Adapter: `binarybuild/compile/libxml2.py`

Public APIs:
- `compile_commit(config, ref, stage, log, profile="static") -> BuildOutput`
- `choose_binary(worktree, functions, preferred="", profile="static") -> BinaryMatch | None`
- `find_binary_by_name(worktree, binary_name, profile="static") -> Path | None`
- `copy_binary(src, dest) -> None`
- `target_filename(project_or_config, version, binary_name, compiler="", opt="") -> str`

Architecture support:
- Explicitly supports `x86_64` and `aarch64` through `SUPPORTED_ARCHITECTURES`.
- Uses only `config.toolchain` commands for CC/CXX, AR/RANLIB/NM/OBJDUMP/OBJCOPY/STRIP/READELF, and propagates its compiler flags to compilation and linking.
- Every AArch64 configure attempt passes `--host=config.toolchain.configure_host`; package discovery is disabled rather than allowing native pkg-config results.
- AArch64 candidates and both sides of every copy are checked with the marker-recorded central `readelf` and must report ELF Machine `AArch64`.
- Passing a `BuildConfig` to `target_filename` delegates to `config.target_binary_name`, preserving existing x86_64 names and the AArch64 prefix.

Build strategy:
- Resolve refs and create detached git worktrees below `config.worktree_root`; never configure or compile in the source checkout.
- Include commit, profile, architecture-qualified build variant, and adapter version in the worktree name. Reuse requires a matching full-toolchain signature marker, the recorded successful build directory, and an architecture-correct ELF candidate.
- Treat an Autotools checkout as ready only when both `configure` and the root `Makefile.in` exist. This prevents a partially failed bootstrap from reaching `config.status` with missing generated inputs.
- For old release tags, run `libtoolize --force --copy` before `autoreconf -fvi` so the legacy `AC_PROG_LIBTOOL` setup supplies `LIBTOOL` to Automake. If that path still fails, run the historical `autogen.sh` bootstrap with `NOCONFIGURE=1` so bootstrap never configures the source tree.
- Prepend the standard system aclocal directories to `ACLOCAL_PATH`. This keeps `/usr/local/bin/aclocal` installations from generating a broken `configure` with literal `PKG_PROG_PKG_CONFIG` or `PKG_CHECK_MODULES` tokens when `pkg.m4` is installed under `/usr/share`.
- Configure in separate `.agentic-build-<profile>-<attempt>` directories. Static builds are preferred so local functions from `xzlib.c` remain available in `xmllint`; shared builds are supported for target variants.
- Prefer liblzma and zlib, disable Python and readline, and then try progressively simpler forms, including a core-only no-lzma/no-zlib fallback for cross toolchains without target development libraries.
- `configure_env` detects legacy `xzlib.c` guarded by `HAVE_LZMA_H` and disables pkg-config for configure/make in those worktrees. Before the upstream XZ build repair, successful liblzma pkg-config discovery skips the header check and silently excludes `xz_decomp` despite `WITH_LZMA=1`. The Autoconf fallback probes the actual header and library with the configured compiler, enabling XZ only when dependencies are available. No feature macros are forced, no CVE/source code is modified, and newer native builds retain normal pkg-config discovery. Adapter version `libxml2-reference-20260909.1` invalidates earlier incomplete-feature caches.
- Build `xmllint` and `xmlcatalog` with debug information, the requested compiler/optimization, disabled inlining, and frame pointers retained. Fall back from the paired tool targets to `xmllint` alone and then the default make target for old release differences.
- Successful builds write a signature marker and may remove successful-command detailed logs according to `config.cleanup_build_logs`. Failed-command logs are retained even if a later fallback succeeds or cleanup is `all`; an unsuccessful overall build retains all its logs.

Binary selection:
- Prefer `.libs/xmllint`, then `xmllint`, `xmlcatalog`, and unstripped `libxml2.so*` fallbacks.
- Keep stable binary names `xmllint`, `xmlcatalog`, and `libxml2` for incremental target lookup.
- Inspect regular and dynamic symbol tables with the marker-recorded `config.toolchain.nm`. Select a candidate containing all requested functions when possible, otherwise return the candidate with the fewest missing functions.
- The static `xmllint` executable is expected to retain both exported library functions such as `xmlStaticCopyNodeList` and local LZMA helpers such as `xz_head` and `xz_decomp`.

Expected coverage:
- Autotools-based libxml2 releases spanning the requested 2012 through 2023 reference commits.
- Builds require the normal Autotools toolchain. Target zlib/liblzma development files improve feature coverage, but core-function builds can fall back to disabling those optional libraries.
- CVE-2015-8035 reference commits `e724879d964d774df9b7969fc846605aa1bac54c` and `f0709e3ca8f8947f2d91ed34e92e38a4c23eae63` require the legacy header-detection path to retain `xz_decomp` when native liblzma pkg-config metadata is installed.

Validation (2026-09-09):
- Both CVE-2015-8035 commits built with `gcc -O0` on x86_64 in static and shared profiles. Selected `xmllint`/`libxml2` artifacts retain `xz_decomp`, `.symtab`, and `.debug_info`; copy integrity, incremental reuse, and XZ-compressed XML parsing passed. The original `xzlib.c`, `xmlIO.c`, and `configure.ac` were unchanged.
- An AArch64 `gcc -O0` static build of the patch commit passed the core-only fourth configure attempt, architecture-checked copying, and reuse. Target zlib/liblzma libraries were unavailable, so this smoke test validates core cross-build support, not AArch64 `xz_decomp` coverage.
- Focused tests in `tests/test_libxml2_compile_adapter.py` cover legacy/newer configuration, central cross-toolchain settings and naming, and successful/failed log retention. Together with architecture and reference-requirement tests, 21 tests passed.
