# curl Compile Adapter Spec

## Overview

`curl.py` is the reusable compile adapter for the curl project. It is called by both the reference build stage and the target build stage. The adapter encapsulates how to obtain an ELF suitable for symbol validation across many generations of curl source code. It handles git worktree management, autotools bootstrap, historical Autoconf cross-compilation compatibility, configure/make retry strategies, CMake fallback, local static dependency stubs, special symbol-only shared-object fallbacks, and final binary candidate selection.

The main entry point is `compile_commit(config, ref, stage, log, profile="static")`. Standard profiles are `static` and `shared`. Additional profile tokens can trigger special behavior, including `gnutls`, `gssapi`, `libidn`, `openldap`, `schannel-wince`, `vtls-mbed-polar`, `schannel-connect`, `source-cookie`, `source-url`, and `source-smb`. These extended profiles exist for older CVEs where the relevant function may live in an optional backend or platform-specific source file, and a normal full curl build is unreliable.

The reference orchestrator routes diffs under `src/` to the static profile first so the selected ELF is the curl tool, not `libcurl`. Tasks involving `gtls_*` functions use explicit `shared-gnutls` / `static-gnutls` profiles, while `mbed_connect_step1` or `polarssl_connect_step1` use the dedicated `vtls-mbed-polar` symbol profile. Target tasks named `libcurl-gnutls` likewise use only explicit GnuTLS profiles. Existing reference pairs are reusable only after both ELF architecture and required side-specific function symbols are revalidated.

All build directories live under `config.worktree_root`. Worktree names include commit, profile, architecture-qualified build variant, and adapter version tokens so incremental runs do not accidentally reuse incompatible builds. Successful builds write a marker. A build is reusable only when the marker matches the current adapter, architecture, complete toolchain contract, compiler, optimization, and profile signature. Detailed successful build logs are removable according to `config.cleanup_build_logs`; failure logs are kept for debugging. Log filenames include the full profile.

## Native TLS Backend Candidates

Plain `static` and `shared` profiles build only the ordinary primary curl configuration.
A genuine GnuTLS variant is built only when the orchestrator explicitly requests a
`static-gnutls` or `shared-gnutls` profile. This prevents unrelated `libcurl` targets
from paying for an unused backend build. No dependencies are installed or stubbed for
this backend. Source preparation and probing live in `_curl_gnutls.py`.

The explicit GnuTLS source tree is a `git archive` of the exact commit under
`<worktree>/.agentic-gnutls/`, with its own source-commit and full build-signature
markers. It is not copied from the configured checkout. It is cleaned together
with its containing worktree. A failed GnuTLS build produces notes and retained
failure logs and is retried on subsequent calls. It is never created by a plain profile.

Explicit GnuTLS candidates are named `libcurl-gnutls` or `curl-gnutls`. Normal
`libcurl` / `curl` names and priority remain unchanged. Candidate discovery requires
matching toolchain/profile signatures and the requested ELF architecture; backend
coverage is never merged across separate binaries.

`compile_commit` returns the registered parent worktree so the builder can clean it
normally. Successful explicit GnuTLS builds publish the same full build signature
on both that parent and the archived source; reuse restores a missing parent marker
from a validated archived build. Candidate discovery uses the requested GnuTLS
profile unchanged, never a doubled `-gnutls-gnutls` suffix. Nested candidates are
hidden until both signatures match. Selection and lookup use the parent signature,
and copying uses the nearest containing build marker, including
the archived backend's marker. This supports the CVE-2024-8096 function pair
`Curl_gtls_verifyserver` / `gtls_client_init` without modifying either function.

GnuTLS profiles fail closed: they do not fall back to OpenSSL, no-TLS builds, or the
dependency-free CMake fallback, and require a defined GnuTLS backend symbol before
writing a success marker. The standard profiles still provide their previous
Autotools/CMake fallback behavior.

The 2013 `gtls_connect_step3` requirement is supported with the real GnuTLS build.
The full CVE-2021-22890 function union is **not** supported by a single native Linux
ELF: it includes other optional TLS libraries, Windows Schannel/SSPI, and macOS
SecureTransport. The adapter reports missing functions; it does not manufacture
their implementations or silently drop requirements. The legacy mbedTLS/PolarSSL
extraction profile still requires both source files and does not cover this 2021
multi-backend task. Source-symbol/stub profiles are not evidence of a functional
native platform backend.

## Architecture and Toolchain Contract

- The adapter explicitly supports `x86_64` and `aarch64` through `SUPPORTED_ARCHITECTURES`.
- Compiler and binutils commands come only from `config.toolchain`: `CC`, `CXX`, `AR`, `RANLIB`, `NM`, `OBJDUMP`, `OBJCOPY`, `STRIP`, and `READELF`. Toolchain compiler flags are applied to Autotools, CMake, dependency-stub, source-symbol, and generated-symbol builds. AArch64 builds disable native `pkg-config` discovery because no target sysroot/package metadata is part of the central contract.
- Every AArch64 Autotools configure attempt includes `--host=config.toolchain.configure_host`. CMake fallback uses the central tools, declares Linux/AArch64 cross-compilation, and pre-seeds historical GNU/POSIX `strerror_r` and `poll` runtime probes so target executables are never run during configure.
- Explicit GnuTLS profiles are x86_64-only. AArch64 standard builds do not run the native dependency probe, and explicit GnuTLS profiles return failure because the central contract does not provide target TLS development packages. Existing AArch64 builds remain supported through their central cross toolchain and existing profiles; there is no native TLS fallback.
- Architecture-qualified worktree names, build markers, and local dependency-stub directories prevent native and cross artifacts from being reused together.
- Candidate discovery filters against the architecture stored in the build marker. Symbol lookup uses the marker's central `NM` command.
- `copy_binary` reads the source worktree marker and filters both architectures by their ELF headers. AArch64 additionally validates the source and destination with the recorded central `READELF` and accepts them only when the ELF `Machine` value is exactly `AArch64`; x86_64 retains header-based copy compatibility.
- Passing a `BuildConfig` as the first argument to `target_filename` delegates to `config.target_binary_name`, preserving unchanged x86_64 names and the `aarch64` prefix. The legacy string form remains supported.

## AI Usage Notes

Read this spec before opening the Python source. For normal build failures, start with `compile_worktree`, `run_bootstrap`, `configure_commands`, `make_commands`, and `compile_cmake_fallback`. For dependency or feature-detection failures, start with `ensure_local_openldap`, `ensure_local_gssapi`, `ensure_local_old_idn`, and `build_env`. For GnuTLS builds, see `compile_commit`, `wants_gnutls`, and `_curl_gnutls.py`. For missing symbols, start with the `wants_*` helpers, the `compile_*_symbol*` helpers, `candidates_for_binary`, and `choose_binary`. If you add a profile token, candidate path, compatibility patch, stub dependency, or public API, update this spec in the same change.

## Public API

- `compile_commit(config, ref, stage, log, profile="static")`
- `choose_binary(worktree, functions, preferred="", profile="static")`
- `find_binary_by_name(worktree, binary_name, profile="static")`
- `copy_binary(src, dest)`
- `target_filename(project_or_config, version, binary_name, compiler="", opt="")`

## Profile Semantics

- `static`: Targets a static curl executable. Candidate sorting prefers `curl`, then `libcurl`. When the worktree contains the historical GSSAPI-guarded FTP `read_data` function, normal attempts enable the local GSSAPI stub first, then retry without GSSAPI for compatibility.
- `shared`: Targets shared `libcurl`. Candidate sorting prefers `libcurl`, then `curl`. When the worktree contains the historical GSSAPI-guarded FTP `read_data` function, normal attempts enable the local GSSAPI stub first, then retry without GSSAPI for compatibility.
- `static-gnutls` / `shared-gnutls`: Builds the full project with real GnuTLS on x86_64, with static/shared libcurl linkage respectively. No TLS stubs, alternate-backend fallback, or implicit invocation from plain profiles.
- `gss` / `gssapi` / `krb5`: Builds a local GSSAPI stub and passes `--with-gssapi=<root>` to configure.
- `idn` / `libidn`: Builds a local old-libidn stub and prefers `--with-libidn=<root>`.
- `ldap` / `openldap`: Builds local OpenLDAP/lber stubs and enables LDAP.
- `schannel-wince`: Extracts the old Schannel WinCE `verify_certificate` function and builds it as a standalone shared object.
- `vtls-mbed-polar`: Extracts mbedTLS/PolarSSL backend connection functions and builds them as a standalone shared object.
- `schannel-connect`: Extracts Schannel `schannel_connect_step1` and builds it as a standalone shared object.
- `source-cookie` / `source-url` / `source-smb`: Directly compiles the corresponding source file into a shared object to preserve source-level function symbols.

## Function Specs

### `BuildOutput`

- Input: `commit: str`, `worktree: Path`, `ok: bool`, `log_paths: list[str]`, optional `notes: str`.
- Output: A dataclass instance.
- Purpose: Represents the structured result of compiling one curl commit.

### `BinaryMatch`

- Input: `path: Path`, `binary_name: str`, `missing: list[str]`.
- Output: A dataclass instance.
- Purpose: Represents how well one candidate ELF covers the expected function list.

### `is_elf(path)`

- Input: `Path | str`.
- Output: `bool`.
- Purpose: Detects whether a file is an ELF executable or shared object.

### `symbol_names(path, nm="nm")`

- Input: ELF file path and optional `nm` command.
- Output: `set[str]`.
- Purpose: Extracts defined regular and dynamic symbols using the selected `nm --defined-only -A` and `nm --defined-only -D -A`, stripping symbol version suffixes such as `@` and `@@`. Local/static definitions remain eligible; undefined imports do not satisfy function coverage.

### `supports_symlinks(path)`

- Input: Directory path.
- Output: `bool`.
- Purpose: Tests whether the output filesystem supports symlinks. curl shared builds only warn on unsupported symlinks instead of forcing a fallback.

### `profile_kind(profile)`

- Input: Profile string.
- Output: `"shared"` or `"static"`.
- Purpose: Normalizes extended profiles into the two main build and candidate-sorting categories.

### `effective_profile(config, requested, log)`

- Input: `BuildConfig`, requested profile, and logger.
- Output: Actual profile string.
- Purpose: Currently logs a warning for shared profiles on filesystems without symlink support, then returns the requested profile.

### `build_token(config, profile)`

- Input: `BuildConfig` and profile.
- Output: Filesystem-safe token string.
- Purpose: Generates part of the worktree name from profile, architecture-qualified build variant, and adapter version.

### `build_marker_path(worktree, profile)`

- Input: Worktree and profile.
- Output: Marker file path.
- Purpose: Locates the success marker for the current profile.

### `build_signature(config, profile)`

- Input: `BuildConfig` and profile.
- Output: Multiline signature string.
- Purpose: Records adapter version, architecture, complete central toolchain contract, compiler, optimization flag, and profile to prevent stale or wrong-architecture build reuse.

### `resolve_commit(repo, ref, log)`

- Input: Git repository path, ref/commit/tag, and logger.
- Output: Commit hash string or `None`.
- Purpose: Resolves any git ref to a concrete commit with `git rev-parse`.

### `ensure_worktree(config, ref, log, profile="static")`

- Input: `BuildConfig`, ref, logger, and profile.
- Output: Worktree `Path` or `None`.
- Purpose: Creates or reuses a detached worktree under `config.worktree_root`.

### `append_env_flags(env, name, flags)`

- Input: Environment dictionary, variable name, and flag list.
- Output: None.
- Purpose: Appends flags to variables such as `CPPFLAGS` or `LDFLAGS` while preserving existing values.

### `build_env(config, profile="")`

- Input: `BuildConfig` and profile.
- Output: Environment variable dictionary.
- Purpose: Sets all compiler/binutils commands from `config.toolchain`, applies its compiler flags plus debug/optimization flags, preserves warning behavior and autotools commands, disables native `pkg-config` for AArch64, and adds profile-specific local dependency paths.

### `profile_tokens(profile)`

- Input: Profile string.
- Output: Lowercase token set.
- Purpose: Splits profile names into feature tokens for the `wants_*` helpers.

### `wants_gssapi(profile)`

- Input: Profile string.
- Output: `bool`.
- Purpose: Detects whether the build needs the GSSAPI/Kerberos stub and configure option.

### `wants_old_idn(profile)`

- Input: Profile string.
- Output: `bool`.
- Purpose: Detects whether the build needs the old libidn stub.

### `wants_openldap(profile)`

- Input: Profile string.
- Output: `bool`.
- Purpose: Detects whether the build needs OpenLDAP/lber stubs and LDAP configure options.

### `wants_schannel_wince(profile)`

- Input: Profile string.
- Output: `bool`.
- Purpose: Detects whether to use the Schannel WinCE `verify_certificate` symbol-only build.

### `wants_gnutls(profile)`

- Input: Profile string.
- Output: `bool`.
- Purpose: Recognizes the `gnutls` token for genuine, backend-restricted builds.

### `wants_vtls_mbed_polar(profile)`

- Input: Profile string.
- Output: `bool`.
- Purpose: Detects whether to use the mbedTLS/PolarSSL backend symbol-only build.

### `wants_schannel_connect(profile)`

- Input: Profile string.
- Output: `bool`.
- Purpose: Detects whether to use the Schannel `schannel_connect_step1` symbol-only build.

### `wants_source_symbol(profile)`

- Input: Profile string.
- Output: `bool`.
- Purpose: Detects whether to compile `cookie`, `url`, or `smb` source directly into a shared object.

### `source_symbol_kind(profile)`

- Input: Profile string.
- Output: `"cookie"`, `"url"`, `"smb"`, or `None`.
- Purpose: Extracts the source-symbol kind from the profile.

### `needs_default_gssapi(worktree)`

- Input: Optional curl worktree path.
- Output: `bool`.
- Purpose: Detects historical `lib/security.c` or `lib/krb5.c` revisions whose `read_data` symbol is guarded by `HAVE_GSSAPI`, allowing standard profiles to retain that symbol without enabling GSSAPI for unrelated curl generations.

### `local_dep_root(config, name)`

- Input: `BuildConfig` and dependency name.
- Output: Local dependency root `Path`.
- Purpose: Stores curl stub dependencies under an architecture-qualified `.agentic-deps/<build-variant>/<name>` path inside the worktree root.

### `build_static_stub(config, root, source, library)`

- Input: `BuildConfig`, stub root directory, C source string, and library name.
- Output: `bool`.
- Purpose: Compiles a single-file C stub with the central compiler and flags, archives/indexes it with the central `AR` and `RANLIB`, then writes a complete build-signature marker.

### `ensure_local_openldap(config)`

- Input: `BuildConfig`.
- Output: Stub root `Path` or `None`.
- Purpose: Generates minimal `ldap.h`/`lber.h` headers plus `libldap.a` and `liblber.a` so old LDAP backends can link.

### `ensure_local_gssapi(config)`

- Input: `BuildConfig`.
- Output: Stub root `Path` or `None`.
- Purpose: Generates minimal GSSAPI headers and `libgssapi.a` so GSSAPI-related historical code can compile.

### `ensure_local_old_idn(config)`

- Input: `BuildConfig`.
- Output: Stub root `Path` or `None`.
- Purpose: Generates old-libidn headers and `libidn.a` for curl versions that include `idna.h` or `stringprep.h`.

### `patch_text_file(path, replacements)`

- Input: File path and a list of `(old, new)` replacements.
- Output: `bool`, true when the file was changed.
- Purpose: Small text replacement utility for compatibility patches.

### `apply_worktree_compat_patches(worktree, log, commit)`

- Input: Worktree, logger, and commit hash.
- Output: None.
- Purpose: Patches old autotools macros, removes the historical inappropriate `AC_REQUIRE([AC_RUN_IFELSE])` that makes Autoconf 2.70+ abort AArch64 cross-configure, invalidates a generated `configure` when that macro is repaired so bootstrap regenerates it, makes `buildconf`/`configure` executable, normalizes the over-broad `wantNTLMhttp` guard written by adapter version `.11`, and guards compound NTLM state access where historical sources require it. The `wantNTLMhttp` declaration itself remains available because curl 7.37 through 7.41 use it outside NTLM-only blocks even when NTLM is disabled.
- GnuTLS compatibility: retains the historical `nettle_MD5Init` library probe and adds a real `nettle_md5_init` fallback for newer Nettle. This narrowly matched configure-only change also invalidates generated `configure`; backend C function bodies are not rewritten.

### `run_bootstrap(config, worktree, build_log_dir, commit, profile, log)`

- Input: `BuildConfig`, worktree, build log directory, commit, profile, and logger.
- Output: `(ok: bool, log_paths: list[str])`.
- Purpose: If `configure` is missing, installs local libtool support files first with `libtoolize --force --copy`, then tries `./buildconf`, `autoreconf -fi`, and `autoreconf -fiv`. The build environment exposes the system aclocal macro directories so historical commits can resolve libtool macros on modern hosts.

### `base_configure_options(include_idn_disable=True)`

- Input: Whether to include the old-libidn disable option.
- Output: Base configure option list.
- Purpose: Disables tests, manuals, warning-as-error behavior, and many optional external dependencies to reduce cross-version build complexity.

### `ldap_options_for_profile(profile)`

- Input: Profile string.
- Output: LDAP configure option list.
- Purpose: Enables LDAP and specifies ldap/lber library names when the profile requests OpenLDAP.

### `ssl_options_for_attempt(attempt)`

- Input: `"openssl-new"`, `"openssl-old"`, `"no-ssl"`, or another attempt name.
- Output: SSL configure option list.
- Purpose: Handles configure option differences across curl generations.

### `idn_options_for_attempt(attempt, old_idn_root=None)`

- Input: IDN attempt name and optional old-libidn stub root.
- Output: IDN configure option list.
- Purpose: Switches between libidn2, old libidn, and disabled IDN strategies.

### `configure_commands(config, profile, worktree=None)`

- Input: `BuildConfig`, profile, and optional curl worktree.
- Output: List of `./configure` command variants.
- Purpose: Generates feature-rich-first configure attempts covering static/shared linkage, LDAP, GSSAPI, IDN, and SSL combinations. When the supplied worktree contains the historical GSSAPI-guarded `read_data`, standard profiles try the local GSSAPI stub first so the symbol remains selectable, then repeat without GSSAPI as a compatibility fallback. Every AArch64 attempt includes the central configure host. A final dependency-free, no-zlib attempt prevents native dependency leakage from blocking cross builds without making optional-feature functions disappear from the first successful candidate.
- GnuTLS profiles generate only GnuTLS-enabled commands, disabling OpenSSL with `--without-openssl` (not the conflicting modern alias `--without-ssl`), disabling LDAP and IDN, and retrying without zlib. Unsupported AArch64 GnuTLS profiles return no commands.

### `make_commands(worktree, env=None)`

- Input: Worktree and optional configured build environment.
- Output: List of make command variants.
- Purpose: Builds `lib` and `src` subdirectories first when possible, then falls back to full `make`. When the environment is supplied, retains configured C/C++ flags and reapplies central toolchain, `-g3`, and requested optimization flags as make variable assignments. Historical curl configure removes debug flags by default; this restores DWARF without enabling `DEBUGBUILD` or curl memory-debug code, and leaves the requested optimization last.

### `make_clean(worktree, build_log_dir, commit, profile, index, env)`

- Input: Worktree, build log directory, commit, profile, configure-attempt index, and environment.
- Output: Clean log path string or `None`.
- Purpose: Runs `make distclean` before each configure retry when a Makefile exists.

### `cmake_bool(value)`

- Input: Python boolean.
- Output: `"ON"` or `"OFF"`.
- Purpose: Formats boolean CMake arguments.

### `cmake_build_dir(worktree, profile)`

- Input: Worktree and profile.
- Output: CMake build directory path.
- Purpose: Creates a profile-isolated out-of-tree CMake build directory.

### `cmake_configure_commands(config, worktree, build_dir, profile)`

- Input: `BuildConfig`, worktree, CMake build directory, and profile.
- Output: CMake configure command list.
- Purpose: Generates minimal-dependency CMake configuration commands that disable tests and many optional protocols, inject every central compiler/binutils command, declare Linux/AArch64 cross-compilation when requested, and pre-seed historical target runtime probes for AArch64.

### `compile_cmake_fallback(config, worktree, build_log_dir, commit, profile, log)`

- Input: `BuildConfig`, worktree, log directory, commit, profile, and logger.
- Output: `(ok: bool, log_paths: list[str])`.
- Purpose: Tries CMake/Ninja when autotools bootstrap fails or all configure/make attempts are exhausted. Returns failure without invoking CMake for GnuTLS profiles, so a backend-free CMake build cannot pass as GnuTLS.

### `extract_function_source(text, name)`

- Input: Source text and a static `CURLcode` function name.
- Output: Function source string or `None`.
- Purpose: Extracts one function body from historical backend source files for symbol-only shared-object builds.

### `export_curlcode_function(body)`

- Input: Function source string.
- Output: Modified function source string.
- Purpose: Replaces `static CURLcode` with exported `CURLcode` so the function symbol is visible to `nm`.

### `compile_symbol_shared(config, worktree, build_log_dir, commit, profile, source, log)`

- Input: `BuildConfig`, worktree, log directory, commit, profile, C source string, and logger.
- Output: `(ok: bool, log_paths: list[str])`.
- Purpose: Compiles generated C source with the central compiler contract into `.agentic-symbols/libcurl-<profile>.so` and rejects a wrong-architecture result.

### `source_symbol_path(kind)`

- Input: `"cookie"`, `"url"`, or `"smb"`.
- Output: Corresponding source-relative path.
- Purpose: Maps a source-symbol kind to the curl source file that should be compiled.

### `compile_source_symbol_object(config, worktree, build_log_dir, commit, profile, log)`

- Input: `BuildConfig`, worktree, log directory, commit, profile, and logger.
- Output: `(ok: bool, log_paths: list[str])`.
- Purpose: For `source-cookie/url/smb` profiles, prepares required headers with an AArch64 host when needed, compiles the chosen source file with the central compiler contract, and rejects a wrong-architecture result.

### `vtls_mbed_polar_source(worktree)`

- Input: Worktree.
- Output: Generated C source string or `None`.
- Purpose: Extracts connection functions from `lib/vtls/mbedtls.c` and `lib/vtls/polarssl.c`, then adds minimal types, macros, and stubs.

### `compile_vtls_mbed_polar_symbols(config, worktree, build_log_dir, commit, log)`

- Input: `BuildConfig`, worktree, log directory, commit, and logger.
- Output: `(ok: bool, log_paths: list[str])`.
- Purpose: Builds the mbedTLS/PolarSSL symbol-only shared object.

### `schannel_connect_source(worktree)`

- Input: Worktree.
- Output: Generated C source string or `None`.
- Purpose: Extracts `schannel_connect_step1` from the Schannel backend and adds minimal Windows SSPI stubs.

### `compile_schannel_connect_symbol(config, worktree, build_log_dir, commit, log)`

- Input: `BuildConfig`, worktree, log directory, commit, and logger.
- Output: `(ok: bool, log_paths: list[str])`.
- Purpose: Builds the Schannel connect symbol-only shared object.

### `schannel_wince_source(worktree)`

- Input: Worktree.
- Output: Generated C source string or `None`.
- Purpose: Extracts the old `verify_certificate` function from `lib/vtls/schannel.c` and adds minimal certificate API stubs.

### `compile_schannel_wince_symbol(config, worktree, build_log_dir, commit, log)`

- Input: `BuildConfig`, worktree, log directory, commit, and logger.
- Output: `(ok: bool, log_paths: list[str])`.
- Purpose: Builds the Schannel WinCE `verify_certificate` symbol-only shared object with the central compiler contract and rejects a wrong-architecture result.

### `write_build_marker(config, worktree, profile)`

- Input: `BuildConfig`, worktree, and profile.
- Output: None.
- Purpose: Writes the success marker after a successful build.

### `has_build_marker(config, worktree, profile)`

- Input: `BuildConfig`, worktree, and profile.
- Output: `bool`.
- Purpose: Checks whether the marker exactly matches the current build signature.

### `parse_marker(text)`

- Input: Build marker text.
- Output: `dict[str, str]`.
- Purpose: Parses newline-delimited `key=value` build metadata.

### `read_marker(path)`

- Input: Marker path.
- Output: `dict[str, str]`.
- Purpose: Reads a build marker safely, returning an empty mapping when unavailable.

### `build_metadata(worktree, profile)`

- Input: Worktree and profile.
- Output: `dict[str, str]`.
- Purpose: Returns the architecture and central toolchain metadata recorded for a completed profile build.

### `artifact_build_metadata(path)`

- Input: Candidate ELF path.
- Output: `dict[str, str]`.
- Purpose: Finds the containing git worktree, then returns the nearest containing current-adapter marker used by copy validation. An archived GnuTLS source marker takes precedence over the parent worktree marker.

### `expected_elf(path, architecture="")`

- Input: Candidate path and optional architecture.
- Output: `bool`.
- Purpose: Requires an executable/shared-object ELF and, when supplied, the requested ELF architecture.

### `has_built_curl(worktree, profile, config=None, require_marker=True)`

- Input: Worktree, profile, optional `BuildConfig`, and whether a matching success marker is required.
- Output: `bool`.
- Purpose: Checks whether the worktree has a primary candidate ELF matching the requested architecture. Plain profiles exclude nested companion candidates; explicit GnuTLS profiles accept the validated archived backend as their primary. GnuTLS builds additionally require a defined `gtls_connect_step3`, `Curl_gtls_connect`, or `Curl_ssl_gnutls` symbol using central `NM`. Completed-build reuse requires the marker; in-progress configure/make attempts may disable that marker requirement.

### `compile_commit(config, ref, stage, log, profile="static")`

- Input: `BuildConfig`, ref, stage name, logger, and profile.
- Output: `BuildOutput`.
- Purpose: Main curl compile entry point. Creates/reuses the detached worktree and delegates plain profiles directly to `compile_worktree`. Explicit GnuTLS profiles probe the dependency, prepare the isolated exact-commit source tree, and build only that backend. On success or validated reuse, they publish the full signature on the returned parent worktree as well as the archived source so public selection APIs use the central architecture/toolchain metadata. Failed builds do not publish a new parent success marker and retain their failure logs. Callers must still reject `BinaryMatch.missing`.

### `compile_worktree(config, worktree, commit, stage, log, profile, build_log_dir)`

- Input: Central config, isolated source tree, resolved commit, stage, logger, profile and log directory.
- Output: `BuildOutput`.
- Purpose: Runs the existing single-profile bootstrap/configure/make, special-symbol, CMake and marker workflow for either a git worktree or an archived companion source. Successful detailed logs follow `config.cleanup_build_logs`; failed builds retain their logs.

### `probe_gnutls(config, worktree, log_path, env)` (`_curl_gnutls.py`)

- Input: Central config, worktree, dependency-probe log path and environment.
- Output: `bool`.
- Purpose: On x86_64, compiles and links a tiny program against real GnuTLS headers/library with the central C compiler and compiler flags. The probe is not executed and its scratch files are temporary children of the worktree. AArch64 returns false without running a native command.

### `prepare_gnutls_source(worktree, commit, log_dir, profile)` (`_curl_gnutls.py`)

- Input: Worktree, exact commit, log directory and safe companion profile.
- Output: `(Path | None, list[str])`.
- Purpose: Uses `git archive` and tar extraction into a temporary child, then renames it to `.agentic-gnutls` after writing the source-commit marker. Reuses only a matching source marker and refuses an unrelated existing directory. Does not modify the user's repository checkout or add a nested git-worktree registration.

### `classify_binary(path)`

- Input: ELF path.
- Output: Normalized binary name such as `libcurl`, `curl`, or the file stem.
- Purpose: Converts different path and filename forms into the binary names used by the builder.

### `candidate_sort_key(item, profile)`

- Input: `(Path, binary_name)` and profile.
- Output: Sort key tuple.
- Purpose: Prefers `libcurl` for shared profiles, `curl` for static profiles, and `.libs` products over less direct matches.

### `candidates_for_binary(worktree, profile="static", architecture="")`

- Input: Worktree, profile, and optional required architecture.
- Output: Sorted list of `(Path, binary_name)` candidates.
- Purpose: Enumerates curl/libcurl ELF candidates from `.agentic-symbols`, `lib/.libs`, `src/.libs`, CMake build directories, and recursive fallback searches, rejecting wrong-architecture ELFs when an architecture is known. Nested `.agentic-gnutls` candidates require matching build metadata and receive backend-qualified names, as do explicit GnuTLS-profile candidates. The nested marker profile is the requested profile for explicit GnuTLS builds, or `<profile>-gnutls` for legacy plain-profile companions; it is never double-suffixed.

### `choose_binary(worktree, functions, preferred="", profile="static")`

- Input: Worktree, expected function list, optional preferred binary name, and profile.
- Output: `BinaryMatch | None`.
- Purpose: Selects the best architecture-matching ELF by candidate priority and symbol coverage using the marker's central `NM`. If `preferred` is provided, candidates with that binary name are tried first.

### `find_binary_by_name(worktree, binary_name, profile="static")`

- Input: Worktree, normalized binary name, and profile.
- Output: ELF path or `None`.
- Purpose: Lets target builds reuse the same binary kind selected for the reference build while filtering against the marker's architecture.

### `readelf_machine(path, readelf)`

- Input: ELF path and `readelf` command.
- Output: ELF machine string.
- Purpose: Reads the locale-stable `Machine` field from the ELF header with the selected tool.

### `validate_copy_artifact(path, metadata)`

- Input: ELF path and recorded build metadata.
- Output: `bool`.
- Purpose: Checks the recorded/header architecture. AArch64 additionally requires an exact central `READELF` result of `Machine: AArch64`; x86_64 remains header-validated so a missing native `readelf` does not regress existing copies.

### `copy_binary(src, dest)`

- Input: Source ELF path and destination path.
- Output: None.
- Purpose: Validates the source architecture, copies it, marks it executable, validates the destination again, and removes rejected output. AArch64 validation uses the recorded central `READELF` on both sides.

### `target_filename(project_or_config, version, binary_name, compiler="", opt="")`

- Input: Project name or `BuildConfig`, version/tag, normalized binary name, optional compiler, and optional optimization flag.
- Output: Stable output binary filename.
- Purpose: Delegates to `config.target_binary_name` when given `BuildConfig`, preserving architecture prefixes. The legacy string form still normalizes compiler/opt into the filename to avoid collisions across build strategies.
