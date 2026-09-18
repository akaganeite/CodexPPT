# ffmpeg compile adapter

Adapter: `binarybuild/compile/ffmpeg.py`

Public APIs:
- `compile_commit(config, ref, stage, log, profile="static") -> BuildOutput`
- `choose_binary(worktree, functions, preferred="", profile="static") -> BinaryMatch | None`
- `find_binary_by_name(worktree, binary_name, profile="static") -> Path | None`
- `copy_binary(src, dest) -> None`
- `target_filename(project_or_config, version, binary_name, compiler="", opt="") -> str`

Architecture and toolchain support:
- The adapter explicitly supports `x86_64` and `aarch64` through `SUPPORTED_ARCHITECTURES`.
- Compiler and binutils commands come from the central `config.toolchain`: `CC`, `CXX`, `AR`, `RANLIB`, `NM`, `OBJDUMP`, `OBJCOPY`, `STRIP`, and `READELF`. Toolchain compiler flags are applied to C, C++, and linker flags.
- FFmpeg configure has no Autoconf-style target `--host` option. For AArch64, every configure attempt translates `config.toolchain.configure_host` into `--cross-prefix=<configure_host>-`, enables cross compilation, selects `--arch=aarch64 --target-os=linux`, and explicitly passes the central compiler, linker-driver, assembler-driver, archive, ranlib, nm, and strip commands. Native `pkg-config` discovery is disabled.
- Worktree names and build markers include the architecture-qualified build variant. Markers also record the full central toolchain contract so incompatible x86_64, AArch64, compiler, or toolchain builds cannot be reused.
- Candidate selection uses the marker-recorded `NM` and filters candidates by the recorded ELF architecture. Missing AArch64 marker tool metadata is never replaced with native tools.
- `copy_binary` validates both the source and destination. AArch64 copies require the marker-recorded central `READELF` and an exact ELF `Machine: AArch64`; rejected copies leave no destination artifact.
- Passing a `BuildConfig` as the first argument to `target_filename` delegates to `config.target_binary_name`, preserving unchanged x86_64 names and the `aarch64` prefix. The legacy string form remains supported.

Build strategy:
- Resolves the requested ref and creates a detached git worktree under `config.worktree_root`.
- Does not modify the user's source repository checkout.
- Worktree names include commit, profile, architecture-qualified build variant, and adapter version so incremental runs do not reuse incompatible builds.
- Builds inside the detached worktree because FFmpeg out-of-tree configure creates a `src` symlink and some dataset filesystems do not support symlinks.
- Keeps adapter build markers in `.agentic-build-<profile>` under the detached worktree.
- Sets all target tools from `config.toolchain`, uses `CFLAGS` and `CXXFLAGS` containing toolchain flags plus `-g3 <opt> -fcommon -Wno-error`, and passes `--optflags=<opt>` to FFmpeg configure.
- Keeps the requested optimization level semantically intact; O2 builds use `-O2` and O0 builds use `-O0` instead of FFmpeg's default release `-O3`.
- Configure attempts prefer debug symbols and non-stripped static outputs. All profiles use `--disable-shared --enable-static` so FFmpeg does not create `.so` symlinks on dataset filesystems that reject symlink creation:
  - `--enable-debug=3 --disable-stripping <library-flags> --optflags=<opt> --disable-asm` plus doc-disabling flags.
  - `--enable-debug=3 --disable-stripping <library-flags> --optflags=<opt> --disable-x86asm` plus doc-disabling flags.
  - relaxed variants without doc flags or asm-specific flags for older FFmpeg releases.
- AArch64 retries keep the full cross-toolchain option set on every attempt. Feature-preserving attempts run before `--disable-autodetect` fallbacks, while all AArch64 attempts disable native `pkg-config` discovery.
- The `cbs-jpeg` reference profile deterministically enables the internal `CONFIG_CBS` and `CONFIG_CBS_JPEG` components in generated FFmpeg configuration before compilation. This keeps CBS JPEG patch functions in the selected `ffmpeg` ELF even though the component is normally selected only by optional VAAPI MJPEG support.
- The `exr-zlib` reference profile passes `--enable-zlib --enable-decoder=exr` and rejects the configure result unless both `CONFIG_ZLIB` and `CONFIG_EXR_DECODER` are enabled. It is used for `dwa_uncompress`; the selected target sysroot must therefore provide AArch64 zlib headers and a linkable target library.
- Each configure retry clears the adapter marker directory and runs `make distclean` in the detached worktree when a previous in-tree FFmpeg configuration is present.
- Build attempts target `ffmpeg_g`, then `ffmpeg`, then the default build target.
- A build is complete when an ELF `ffmpeg_g` or `ffmpeg` exists. `ffmpeg_g` and `ffmpeg` map to stable dataset binary name `ffmpeg`; shared libraries are still recognized as fallback candidates if an external compatible build exposes them.
- Successful builds write a marker containing adapter/compiler/opt/profile and may have detailed build logs removed according to `config.cleanup_build_logs`.

Binary selection:
- Candidate search checks the build marker directory first, then the detached worktree.
- Both `ffmpeg_g` and `ffmpeg` map to dataset binary name `ffmpeg`.
- Versioned FFmpeg shared libraries under `libav*/*.so*` are fallback ELF candidates and normalize to unversioned dataset names when present.
- `choose_binary` uses the marker-recorded `nm` and `nm -D`, strips symbol version suffixes, and returns the candidate containing all requested functions when possible. If no complete match exists, it returns the candidate with the fewest missing functions.

Expected coverage:
- Legacy FFmpeg datasets compile target releases and reference commits into the `ffmpeg` executable, historically emitted as `ffmpeg_g` for debug builds.
