# OpenSSL Compile Adapter Spec

## Overview

`openssl.py` is the reusable compile adapter for the OpenSSL project. It is called by both the reference build stage and the target build stage. The adapter never modifies the user-provided source checkout directly. Instead, it creates an isolated, architecture-qualified git worktree under `config.worktree_root` for the requested commit/profile/build variant, applies minimal build-compatibility patches inside that worktree, configures and builds OpenSSL, then exposes helper APIs for selecting and copying the resulting ELF binary.

The main entry point is `compile_commit(config, ref, stage, log, profile="static")`. On success, it returns a `BuildOutput` whose `worktree` points to the compiled worktree. The builder then calls `choose_binary` or `find_binary_by_name` to select a concrete ELF. Detailed configure/make logs are written under the current run log directory, usually `log/.../trace/<stage>_builds/`. Successful logs are removable according to `config.cleanup_build_logs`; failure logs are kept for debugging.

The adapter mainly supports `static`, `shared`, `shared-libcrypto`, and `shared-libssl` profiles. If the profile contains `zlib`, the configure command receives a zlib option. The reference orchestrator prioritizes `static-zlib` and then `shared-zlib` for TLS certificate-compression functions such as `tls13_process_compressed_certificate`, because that code is omitted from ordinary builds without compression support. Static builds prefer the `apps/openssl` executable, while shared builds prefer `libssl` or `libcrypto`. The targeted shared profiles build direct shared-object targets such as `libcrypto.so.3` before falling back to broader `build_sw` or full builds. Shared builds are still attempted on filesystems that do not support symlinks because OpenSSL can often produce the real shared-object ELF before link/symlink steps fail. A nonzero make is sufficient for binary extraction when all ELFs required by the profile have been produced.

The target orchestrator uses shared-first ordering for `libcrypto` and `libssl`, and also for the `openssl` executable from 0.9.x and 1.0.x releases. Those older releases can leave builtin-engine calls unresolved in a static cross-link even when the corresponding engines were disabled; the shared build produces the required executable without spending six static configure attempts first. Newer `openssl` executable targets retain static-first ordering.

OpenSSL 3 legacy-provider functions, including `rc4_hmac_md5_set_ctx_params`, reside in `providers/legacy.so` rather than the main libraries or executable. The adapter also considers this exact module path, with the stable binary name `legacy`, after the existing candidates. Generic static/shared builds require the legacy module when the generated Makefile declares it in `MODULES`; `no-shared` alone does not disable provider modules. Static builds explicitly try the declared `providers/legacy.so` target after `apps/openssl`, then retain the broader build fallbacks. Older releases and builds without that module keep their previous build requirements, and targeted `shared-libcrypto`/`shared-libssl` profiles still require only their requested library. No source algorithm or CVE-specific code is changed to expose the function. Adapter version `openssl-reference-20260909.1` invalidates earlier incomplete-build markers/worktree names.

## Architecture and Toolchain Contract

- The adapter explicitly declares `SUPPORTED_ARCHITECTURES = ("x86_64", "aarch64")`. Existing x86-64 behavior remains supported, and unsupported architectures fail before worktree creation or compilation.
- Worktree names and reusable-build signatures include the architecture-qualified `config.build_variant` and adapter version. A build from one architecture, compiler, optimization, or toolchain cannot be reused for another.
- Tool selection comes only from `config.toolchain`: `c_compiler`, `cxx_compiler`, `ar`, `ranlib`, `nm`, `objdump`, `objcopy`, `strip`, `readelf`, `configure_host`, and `compiler_flags`. The adapter exports the corresponding `CC`, `CXX`, `AR`, `RANLIB`, `NM`, `OBJDUMP`, `OBJCOPY`, `STRIP`, and `READELF` variables, clears OpenSSL's generic `CROSS_COMPILE` prefix, and propagates the central compiler flags into compile and link flags. AArch64 builds never silently substitute native commands or package discovery.
- Before an AArch64 build, `build_env` removes ambient compiler, assembler, linker, preprocessor, include-path, library-path, resource-compiler, and pkg-config variables that could inject native host state. Ambient `LDFLAGS` are not preserved: only `config.toolchain.compiler_flags` seed AArch64 `LDFLAGS`, while those same central flags seed `CFLAGS` and `CXXFLAGS` before the adapter adds debug and optimization flags.
- The OpenSSL configure target is derived from `config.toolchain.configure_host`: x86-64 uses `linux-x86_64`, while an AArch64 host such as `aarch64-linux-gnu` prefers `linux-aarch64`. OpenSSL releases that predate that target use the architecture-neutral 64-bit `linux-generic64` target when it is defined by the checked-out source. Both paths keep the exact AArch64 cross tools in force; AArch64 attempts never use an x86 target or fall back to native `./config` detection.
- Successful markers record the full toolchain, including the exact `nm` and `readelf` commands. Candidate discovery and symbol matching use this marker metadata so later builder calls retain the architecture/toolchain context after `compile_commit` returns.
- AArch64 candidate selection requires the marker-recorded `readelf` to report ELF Machine `AArch64`. `copy_binary` validates both the source and copied destination with that same command and removes/rejects the destination if either check fails.
- When `target_filename` receives a `BuildConfig`, it delegates to `config.target_binary_name(version, binary_name)`. This preserves existing x86-64 naming and retains the `aarch64` prefix in architecture-qualified target variants. The legacy string-project calling form remains available.

## AI Usage Notes

When modifying this adapter, read this spec first and then inspect only the relevant Python functions. For old OpenSSL build failures, start with `apply_worktree_compat_patches`, `configure_commands`, `make_commands`, `has_built_openssl`, and the binary candidate selection helpers. If you add a profile, candidate path, compatibility patch, or public API, update this spec in the same change.

## Public API

- `compile_commit(config, ref, stage, log, profile="static")`
- `choose_binary(worktree, functions, preferred="", profile="static")`
- `find_binary_by_name(worktree, binary_name, profile="static")`
- `copy_binary(src, dest)`
- `target_filename(project: str | BuildConfig, version, binary_name, compiler="", opt="")`

## Function Specs

### `BuildOutput`

- Input: `commit: str`, `worktree: Path`, `ok: bool`, `log_paths: list[str]`, optional `notes: str`.
- Output: A dataclass instance.
- Purpose: Represents the structured result of compiling one OpenSSL commit.

### `BinaryMatch`

- Input: `path: Path`, `binary_name: str`, `missing: list[str]`.
- Output: A dataclass instance.
- Purpose: Represents how well one candidate ELF covers the expected function list. An empty `missing` list means a full match.

### `is_elf(path)`

- Input: `Path | str` pointing to a file.
- Output: `bool`; true only for ELF executable or shared-object files.
- Purpose: Filters out non-ELF files, archives, scripts, and other unsuitable binary outputs.

### `symbol_names(path, nm="nm")`

- Input: `Path` pointing to an ELF file and an optional `nm` command.
- Output: `set[str]` of symbol names from the regular and dynamic symbol tables; returns an empty set if the selected tool fails.
- Purpose: Provides symbol data for `choose_binary`. Normal selection passes the exact marker-recorded `config.toolchain.nm`, which is required for AArch64.

### `build_token(config, profile)`

- Input: `BuildConfig` and profile.
- Output: Filesystem-safe token containing the profile, architecture-qualified build variant, and adapter version.
- Purpose: Prevents worktree reuse across incompatible architectures, compiler/optimization variants, or adapter revisions.

### `ensure_worktree(config, ref, log, profile="static")`

- Input: `BuildConfig`, a git ref/commit/tag, a stage logger, and a profile.
- Output: A reusable or newly created worktree `Path`; `None` if the ref cannot be resolved or the path cannot be reused.
- Purpose: Creates a detached git worktree under `config.worktree_root` without changing the user's repository checkout. The path incorporates `build_token(config, profile)` so architecture and toolchain variants remain isolated.

### `build_env(config)`

- Input: `BuildConfig`, including its central `toolchain`, compiler, architecture, and optimization.
- Output: Environment variable dictionary.
- Purpose: Sets `CC`, `CXX`, `AR`, `RANLIB`, `NM`, `OBJDUMP`, `OBJCOPY`, `STRIP`, and `READELF` strictly from `config.toolchain`; clears `CROSS_COMPILE`; and disables package discovery for AArch64. AArch64 first sanitizes ambient compiler/linker/preprocessor/include/library/pkg-config state, does not retain ambient `LDFLAGS`, sets `LDFLAGS` only from central compiler flags, and sets `CFLAGS`/`CXXFLAGS` from central compiler flags plus debug information and the requested optimization.

### `configure_defines_target(worktree, target)` and `configure_target(config, worktree=None)`

- Input: A configured source worktree plus target name for detection, and `BuildConfig`, principally `architecture` and `toolchain.configure_host`, for selection.
- Output: OpenSSL Configure target string.
- Purpose: Validates that `toolchain.configure_host` matches `config.architecture`, then maps the central host contract to the project-specific target. AArch64 prefers `linux-aarch64` and uses `linux-generic64` only when the release does not define the former and does define the latter; this supports old releases without selecting an x86 or native target.

### `supports_symlinks(path)`

- Input: Directory `Path` to test.
- Output: `bool`.
- Purpose: Detects whether the output filesystem supports symlinks, which matters for shared OpenSSL builds and header links.

### `profile_kind(profile)`

- Input: Profile string.
- Output: `"shared"` or `"static"`.
- Purpose: Normalizes extended profiles into the two build strategy categories.

### `profile_options(profile)`

- Input: Profile string.
- Output: Extra OpenSSL configure options.
- Purpose: Currently detects `zlib` and returns `["zlib"]`.

### `static_compat_options()`

- Input: None.
- Output: Static-build compatibility options.
- Purpose: Disables modules such as engine/hw/gost that often complicate old static builds.

### `effective_profile(config, requested, log)`

- Input: `BuildConfig`, requested profile, and logger.
- Output: The actual profile to use.
- Purpose: Preserves the requested profile. For shared requests on filesystems without symlink support, logs a warning but still attempts the shared build so `libssl` or `libcrypto` ELF candidates can be extracted.

### `build_marker_path(worktree, profile)`

- Input: Worktree path and profile.
- Output: Marker file path.
- Purpose: Locates the marker used to identify a successful reusable build.

### `build_signature(config, profile)`

- Input: `BuildConfig` and profile.
- Output: Multiline signature string.
- Purpose: Records adapter version, architecture, compiler, optimization, profile, triple, every central tool command, configure host, and compiler flags so stale or cross-architecture builds are not reused incorrectly.

### Marker metadata helpers

- Input: Marker text/path, or a compiled worktree/artifact path plus profile where applicable.
- Output: Parsed `dict[str, str]` metadata, or an empty dictionary when no valid marker is available.
- Purpose: `parse_marker`, `read_marker`, `build_metadata`, and `artifact_build_metadata` preserve the build architecture plus marker-recorded `nm` and `readelf` commands for binary selection and copy validation.

### `has_built_openssl(worktree, profile, config=None)`

- Input: Worktree, profile, and optional `BuildConfig`.
- Output: `bool`.
- Purpose: Checks whether the worktree already contains a usable OpenSSL ELF for the requested profile. `shared-libcrypto` requires a `libcrypto.so*` ELF, `shared-libssl` requires a `libssl.so*` ELF, generic shared profiles accept either shared library, and static profiles require `apps/openssl`. Generic shared and static profiles additionally require an architecture-valid `providers/legacy.so` when declared in Makefile `MODULES`. If `config` is provided, the full marker signature and architecture validation must also match; AArch64 reuse requires the marker-recorded `readelf` to report Machine `AArch64` for every required ELF, including the legacy module.

### `write_build_marker(config, worktree, profile)`

- Input: `BuildConfig`, worktree, and profile.
- Output: None.
- Purpose: Writes `.agentic-build-<profile>.marker` after a successful build.

### `apply_worktree_compat_patches(worktree, log, commit)`

- Input: Worktree, logger, and commit hash.
- Output: None.
- Purpose: Applies minimal compatibility patches for old OpenSSL sources, including Perl `File::Glob` syntax and known generated-build syntax issues.

### `enforce_configured_opt(worktree, opt, log, commit)`

- Input: Worktree, desired optimization flag, logger, and commit hash.
- Output: None.
- Purpose: Rewrites generated Makefile `-O*` flags to the user-requested `config.opt` after configure.

### `makefile_tokens(makefile, variable)`

- Input: Makefile path and variable name.
- Output: Token list; empty list on read failure.
- Purpose: Parses Makefile variables such as `EXHEADER`, including backslash-continued lines.

### `materialize_header_links(worktree, log, commit)`

- Input: Worktree, logger, and commit hash.
- Output: None.
- Purpose: Copies OpenSSL headers into `include/openssl/` when the filesystem cannot represent the header symlinks expected by old builds.

### `materialize_shared_library_aliases(worktree, log, commit)`

- Input: Worktree, logger, and commit hash.
- Output: None.
- Purpose: Rewrites generated Makefile shared-library alias steps from `ln -s libcrypto.so.3 libcrypto.so` / `ln -s libssl.so.3 libssl.so` to copy commands when the filesystem cannot create symlinks. This lets shared `libssl` builds continue after producing real `.so.N` ELF files.

### `should_run_make_depend(worktree)`

- Input: Worktree.
- Output: `bool`.
- Purpose: Decides whether `make depend` is appropriate for the current OpenSSL tree. It skips modern generated-build trees and cases with missing test sources.

### `configure_commands(config, profile, worktree=None)`

- Input: `BuildConfig`, profile, and optional worktree for release-specific target detection.
- Output: List of configure command variants.
- Purpose: Generates OpenSSL configure attempts from strict to relaxed, covering static/shared and optional zlib behavior. Every `perl ./Configure` attempt receives `config.toolchain.compiler_flags` explicitly so old OpenSSL releases that ignore environment `CFLAGS` still receive the cross-compiler flags. AArch64 commands use `linux-aarch64` when supported or the non-x86 `linux-generic64` compatibility target for older releases, and never include a native `./config` fallback; x86-64 retains compatible explicit-Configure and legacy `./config` variants.

### `configured_ar_override(config, worktree=None)`

- Input: `BuildConfig` and an optional configured worktree.
- Output: An `AR=...` make assignment using `config.toolchain.ar`.
- Purpose: Replaces the archive executable with the central toolchain command while preserving legacy generated Makefile suffixes such as `$(ARFLAGS) r`, which older OpenSSL releases require as part of their `AR` variable.

### `make_tool_overrides(config, worktree=None)`

- Input: `BuildConfig`, its central toolchain, and an optional configured worktree.
- Output: Make variable assignments for `CC`, `CXX`, `AR`, `RANLIB`, `NM`, `OBJDUMP`, `OBJCOPY`, `STRIP`, and `READELF`, plus an empty `CROSS_COMPILE` assignment.
- Purpose: Pins every OpenSSL make invocation to the central tools, including old generated Makefiles that may otherwise select native commands or prepend their own tool prefix. The AR assignment comes from `configured_ar_override` so required legacy suffix arguments are retained.

### `make_command(config, target="", parallel=True, worktree=None)`

- Input: `BuildConfig`, optional make target, whether to use the available CPU count for parallel jobs, and an optional configured worktree.
- Output: One complete make command list containing central tool overrides and, when requested, a target.
- Purpose: Builds consistent clean/depend/build commands without losing the cross-toolchain contract or the configured worktree's legacy AR suffix between configure and make.

### `make_commands(config, profile, worktree=None)`

- Input: `BuildConfig`, profile, and optional worktree.
- Output: List of make command variants.
- Purpose: Chooses appropriate make targets such as `build_apps`, `build_generated`, `apps/openssl`, the declared `providers/legacy.so` module for static builds, direct shared library targets for `shared-libcrypto`/`shared-libssl`, `build_sw`, or full `make`, while keeping the configured central cross-toolchain environment in force. The legacy target is attempted only when present in Makefile `MODULES`, so old releases never receive an invented module target.

### `compile_openssl_commit(config, ref, stage, log, profile="static")`

- Input: `BuildConfig`, git ref, stage name, logger, and profile.
- Output: `BuildOutput`.
- Purpose: Actual OpenSSL compile implementation. It rejects unsupported architectures, prepares an architecture-qualified worktree, patches compatibility issues, tries configure/make variants, verifies the resulting architecture, writes the full-toolchain build marker, and cleans successful command logs when configured. Logs from failed clean/configure/depend/make commands are retained even if a later fallback succeeds or a nonzero make still produces usable artifacts, including under cleanup policy `all`. A completely failed build retains all its logs. `BuildOutput.log_paths` lists all attempted command logs, including successfully removed logs.

### `compile_commit(config, ref, stage, log, profile="static")`

- Input: Same as `compile_openssl_commit`.
- Output: `BuildOutput`.
- Purpose: Public builder entry point; currently delegates to `compile_openssl_commit`.

### `candidates_for_binary(worktree, profile="static", architecture="", readelf="")`

- Input: Compiled worktree, profile, and optional architecture/readelf constraints. When both constraints are omitted, they are loaded from marker metadata.
- Output: `list[tuple[Path, str]]`, where each item is a candidate path and normalized binary name.
- Purpose: Enumerates ELF candidates for `openssl`, `libssl`, and `libcrypto` with profile-specific priority, followed by the exact `providers/legacy.so` path under binary name `legacy`, rejecting architecture mismatches, archives, objects, and symlinks. AArch64 candidates, including the legacy module, require `readelf -hW` to report Machine `AArch64`.

### `choose_binary(worktree, functions, preferred="", profile="static")`

- Input: Worktree, expected function names, optional preferred binary name, and profile.
- Output: `BinaryMatch | None`.
- Purpose: Loads architecture, `nm`, and `readelf` from the build marker; selects the valid candidate ELF that covers the most expected functions, returning immediately on a full match. It does not fall back to native `nm`/`readelf` for marked AArch64 builds.

### `find_binary_by_name(worktree, binary_name, profile="static")`

- Input: Worktree, normalized binary name, and profile.
- Output: Matching ELF `Path` or `None`.
- Purpose: Lets target builds reuse the same binary kind selected for the reference build while enforcing the marker-recorded architecture and `readelf` checks.

### `readelf_machine(path, readelf)` and architecture validation helpers

- Input: ELF path, architecture, marker metadata, and/or explicit `readelf` command depending on the helper.
- Output: Parsed ELF Machine string or a validation boolean.
- Purpose: `readelf_machine`, `expected_elf`, `profile_has_expected_output`, and `validate_copy_artifact` combine the central architecture parser with the marker-recorded tool. For AArch64, a valid artifact must be an ELF for the requested architecture and must report exactly `AArch64` in the readelf header.

### `copy_binary(src, dest)`

- Input: Source and destination as `Path | str`.
- Output: None.
- Purpose: Resolves build metadata from the source worktree, validates the source, creates the destination directory, copies the ELF, marks it executable, and validates the destination. For AArch64, both validations use the marker-recorded central `readelf`; a failed destination is removed.

### `target_filename(project: str | BuildConfig, version, binary_name, compiler="", opt="")`

- Input: Either a `BuildConfig` or legacy project-name string, version/tag, normalized binary name, optional compiler, and optional optimization flag.
- Output: Stable output binary filename.
- Purpose: For `BuildConfig`, delegates to `config.target_binary_name(version, binary_name)` so architecture-qualified variants retain the `aarch64` prefix while x86-64 naming remains unchanged. For the legacy string form, preserves the existing normalized compiler/optimization suffix behavior.
