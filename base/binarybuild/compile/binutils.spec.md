# binutils compile adapter

Adapter: `binarybuild/compile/binutils.py`

Public APIs:
- `compile_commit(config, ref, stage, log, profile="static") -> BuildOutput`
- `choose_binary(worktree, functions, preferred="", profile="static") -> BinaryMatch | None`
- `find_binary_by_name(worktree, binary_name, profile="static") -> Path | None`
- `copy_binary(src, dest) -> None`
- `target_filename(project, version, binary_name, compiler="", opt="") -> str`

Architecture support:
- The adapter explicitly supports `x86_64` and `aarch64` through `SUPPORTED_ARCHITECTURES`.
- AArch64 builds use only the central `config.toolchain` commands for `CC`, `CXX`, `AR`, `RANLIB`, `NM`, `OBJDUMP`, `OBJCOPY`, `STRIP`, and `READELF`, apply its compiler flags, and configure with `--host=config.toolchain.configure_host`.
- Worktree names and build markers include the architecture-qualified build variant, so an x86_64 build cannot be reused as an AArch64 build. The marker also records the successful configure-attempt directory; completed builds search only that directory instead of mixing artifacts from failed attempts.
- Candidate discovery rejects ELF files whose machine does not match the requested architecture and rejects candidates without a readable regular symbol table. Symbol lookup uses the `NM` recorded from the central toolchain.
- `copy_binary` validates both the source and copied ELF with the recorded central `readelf`; AArch64 artifacts are accepted only when `Machine` is exactly `AArch64`.
- Passing a `BuildConfig` as the first argument to `target_filename` delegates to `config.target_binary_name`, preserving unchanged x86_64 names and the `aarch64` prefix for cross-build variants. The legacy string form remains available for existing callers.

Build strategy:
- Resolves the requested ref in the source repository and creates a detached git worktree under `config.worktree_root`.
- Uses an out-of-tree build directory inside that worktree: `.agentic-build-<profile>-<attempt>`.
- Does not configure or compile in the user's source repository checkout.
- Sets compiler and binutils commands from the central toolchain contract, plus `CFLAGS` and `CXXFLAGS` with toolchain compiler flags and debug-friendly flags: `-g3`, requested optimization, `-fcommon`, `-fno-omit-frame-pointer`, and `-fno-inline`. `-fcommon` is required for older binutils releases that otherwise fail to link on modern GCC with multiple-definition errors.
- Sets `MAKEINFO=true` and `TEXI2DVI=true` in the environment and repeats both as command-line make variables. Old generated Makefiles override environment-only values with their bundled `missing makeinfo` wrapper, so the command-line assignments are required to avoid documentation failures.
- Before configuration, idempotently patches the generated top-level `configure` check used by binutils 2.40 and later so a present `gdb/` directory requires GMP/MPFR only when GDB is enabled. This keeps `--disable-gdb` target-only cross builds from requiring unused AArch64 GMP/MPFR libraries and modifies only the detached worktree.
- Runs top-level `configure` with alternate option sets. AArch64 adds the central `--host` value to every option set. Every option set builds binutils/BFD/libiberty-oriented outputs with `--enable-targets=all`, disables GDB/GDBserver/sim/gas/gprofng/gold where accepted, disables Werror and NLS, and avoids optional system dependencies where possible.
- For `profile` values starting with `shared`, configures with `--enable-shared --disable-static`; otherwise uses `--disable-shared --enable-static`. Reference orchestration tries `static` first because changed BFD/binutils functions are reliably retained in the final executable there; `shared` is the fallback.
- Build attempts run only targeted top-level make targets: `all-bfd`, `all-opcodes`, `all-libiberty`, `all-binutils`, and `all-ld`. They intentionally avoid a full top-level `make` fallback because it can enter GDB/sim subtrees and make target-only dataset builds much slower.
- A build is not marked complete until it has produced `libbfd` plus at least one executable candidate from `readelf`, `objdump`, or `c++filt`. This avoids returning after `all-bfd` when readelf/libiberty CVEs still need executable symbols.
- Successful builds write an adapter/architecture/toolchain/compiler/opt/profile marker with the selected attempt directory and may have detailed build logs removed by `config.cleanup_build_logs`; failed logs are retained.

Binary selection:
- Candidate search covers out-of-tree build directories and the worktree.
- Preferred candidates include `binutils/readelf`, `binutils/.libs/readelf`, `binutils/objdump`, `binutils/.libs/objdump`, `binutils/nm-new`, `binutils/.libs/nm-new`, `binutils/cxxfilt`, `binutils/.libs/cxxfilt`, `binutils/c++filt`, `binutils/.libs/c++filt`, `ld/ld-new`, `ld/.libs/ld-new`, `bfd/.libs/libbfd.so*`, `opcodes/.libs/libopcodes.so*`, and `libctf/.libs/libctf.so*`.
- Binary names are normalized for stable pair matching:
  - `nm-new` -> `nm`
  - `ld-new` -> `ld`
  - `cxxfilt` and `c++filt` -> `c++filt`
  - `libbfd.so*` -> `libbfd`
  - `libopcodes.so*` -> `libopcodes`
  - `libctf.so*` -> `libctf`
- `choose_binary` uses the build marker's central toolchain `nm` and `nm -D`, strips symbol version suffixes, and returns the candidate containing all requested functions when possible. If no complete match exists, it returns the candidate with the fewest missing functions.
- Already stripped installed executables are never accepted as source-build candidates; this prevents debug splitting from producing symbol-less companion files.

Expected CVE coverage:
- `binutils/dwarf.c` and `binutils/readelf.c` changes should normally resolve to `readelf`.
- `bfd/xcofflink.c` and related XCOFF relocation changes should normally resolve to `libbfd` in shared profile, with executable candidates as fallback.
- `libiberty` demangler changes should normally resolve to `c++filt`/`cxxfilt` or another binutils executable linked with libiberty.
