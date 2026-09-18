from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from binarybuild.build_log_cleanup import remove_build_logs
from builder.architecture import elf_architecture, matches_elf_architecture
from builder.config import BuildConfig, path_token
from builder.logging import StageLogger, current_log_root
from utils.command import run_command

ADAPTER_VERSION = "binutils-reference-20260812.2"
SUPPORTED_ARCHITECTURES = ("x86_64", "aarch64")

GDB_GMP_CHECK = """if test -d ${srcdir}/gdb ; then
  require_gmp=yes
fi"""
GDB_GMP_CHECK_WITH_DISABLE = """if test -d ${srcdir}/gdb && test "x$enable_gdb" != xno ; then
  require_gmp=yes
fi"""


@dataclass
class BuildOutput:
    commit: str
    worktree: Path
    ok: bool
    log_paths: list[str]
    notes: str = ""


@dataclass
class BinaryMatch:
    path: Path
    binary_name: str
    missing: list[str]


def is_elf(path: Path | str) -> bool:
    path = Path(path)
    try:
        with path.open("rb") as f:
            header = f.read(18)
        if len(header) < 18 or header[:4] != b"\x7fELF":
            return False
        endian = header[5]
        e_type = struct.unpack("<H" if endian == 1 else ">H", header[16:18])[0]
        return e_type in (2, 3)
    except OSError:
        return False


def symbol_names(path: Path, nm: str = "nm") -> set[str]:
    names: set[str] = set()
    for command in ([nm, "-A", str(path)], [nm, "-D", "-A", str(path)]):
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except OSError:
            continue
        if proc.returncode:
            continue
        for line in proc.stdout.splitlines():
            parts = line.rsplit(None, 1)
            if len(parts) != 2:
                continue
            name = parts[1].split("@@", 1)[0].split("@", 1)[0]
            if not name:
                continue
            names.add(name)
            names.add(name.lstrip("_"))
    return names


def profile_kind(profile: str) -> str:
    return "shared" if profile.startswith("shared") else "static"


def build_token(config: BuildConfig, profile: str) -> str:
    profile_id = path_token(profile, profile_kind(profile))
    variant_id = path_token(config.build_variant, "variant")
    adapter_id = path_token(ADAPTER_VERSION, "adapter")
    return f"{profile_id}-{variant_id}-{adapter_id}"


def resolve_commit(repo: Path, ref: str, log: StageLogger) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{ref}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode:
        log.error("cannot resolve binutils ref", ref=ref, stderr=proc.stderr.strip())
        return None
    return proc.stdout.strip()


def ensure_worktree(config: BuildConfig, ref: str, log: StageLogger, profile: str = "static") -> Path | None:
    config.worktree_root.mkdir(parents=True, exist_ok=True)
    commit = resolve_commit(config.repo, ref, log)
    if not commit:
        return None
    worktree = config.worktree_root / f"{commit}-{build_token(config, profile)}"
    if (worktree / ".git").exists():
        head = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if head.returncode == 0 and head.stdout.strip() == commit:
            return worktree
    if worktree.exists():
        log.warn("binutils worktree path exists but is not reusable", ref=ref, path=str(worktree))
        return None
    add = subprocess.run(
        ["git", "-C", str(config.repo), "worktree", "add", "--detach", str(worktree), commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if add.returncode:
        log.error("failed to create binutils worktree", ref=ref, path=str(worktree), stderr=add.stderr.strip())
        return None
    return worktree


def append_env_flags(env: dict[str, str], name: str, flags: list[str]) -> None:
    existing = env.get(name, "").strip()
    addition = " ".join(flag for flag in flags if flag)
    env[name] = " ".join(part for part in (existing, addition) if part)


def build_env(config: BuildConfig) -> dict[str, str]:
    env = os.environ.copy()
    toolchain = config.toolchain
    env.update(
        {
            "CC": toolchain.c_compiler,
            "CXX": toolchain.cxx_compiler,
            "AR": toolchain.ar,
            "RANLIB": toolchain.ranlib,
            "NM": toolchain.nm,
            "OBJDUMP": toolchain.objdump,
            "OBJCOPY": toolchain.objcopy,
            "STRIP": toolchain.strip,
            "READELF": toolchain.readelf,
        }
    )
    flags = [
        *toolchain.compiler_flags,
        "-g3",
        config.opt.strip(),
        "-fcommon",
        "-fno-omit-frame-pointer",
        "-fno-inline",
        "-Wno-error",
        "-Wno-error=implicit-function-declaration",
        "-Wno-error=incompatible-pointer-types",
        "-Wno-error=int-conversion",
    ]
    common_flags = " ".join(flag for flag in flags if flag)
    env["CFLAGS"] = common_flags
    env["CXXFLAGS"] = common_flags
    env["MAKEINFO"] = "true"
    env["TEXI2DVI"] = "true"
    env["YACC"] = env.get("YACC", "bison -y")
    append_env_flags(env, "LDFLAGS", [*toolchain.compiler_flags, "-Wl,--no-as-needed"])
    return env


def build_dir(worktree: Path, profile: str) -> Path:
    return worktree / f".agentic-build-{path_token(profile, 'profile')}"


def build_marker_path(worktree: Path, profile: str) -> Path:
    return build_dir(worktree, profile) / ".agentic-build.marker"


def build_signature(config: BuildConfig, profile: str) -> str:
    toolchain = config.toolchain
    return (
        f"adapter={ADAPTER_VERSION}\n"
        f"architecture={config.architecture}\n"
        f"compiler={config.compiler}\n"
        f"opt={config.opt}\n"
        f"profile={profile}\n"
        f"cc={toolchain.c_compiler}\n"
        f"cxx={toolchain.cxx_compiler}\n"
        f"ar={toolchain.ar}\n"
        f"ranlib={toolchain.ranlib}\n"
        f"nm={toolchain.nm}\n"
        f"objdump={toolchain.objdump}\n"
        f"objcopy={toolchain.objcopy}\n"
        f"strip={toolchain.strip}\n"
        f"readelf={toolchain.readelf}\n"
        f"configure_host={toolchain.configure_host}\n"
        f"compiler_flags={' '.join(toolchain.compiler_flags)}\n"
    )


def write_build_marker(config: BuildConfig, worktree: Path, profile: str, build: Path) -> None:
    if build.parent.resolve() != worktree.resolve():
        raise ValueError(f"binutils build directory is outside its worktree: {build}")
    marker = build_marker_path(worktree, profile)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(f"{build_signature(config, profile)}build_dir={build.name}\n", encoding="utf-8")


def has_build_marker(worktree: Path, profile: str, config: BuildConfig) -> bool:
    metadata = read_marker(build_marker_path(worktree, profile))
    expected = parse_marker(build_signature(config, profile))
    if not metadata or any(metadata.get(key) != value for key, value in expected.items()):
        return False
    build_name = metadata.get("build_dir", "")
    return bool(
        build_name.startswith(".agentic-build-")
        and Path(build_name).name == build_name
        and (worktree / build_name).is_dir()
    )


def parse_marker(text: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        metadata[key] = value
    return metadata


def read_marker(path: Path) -> dict[str, str]:
    try:
        return parse_marker(path.read_text(encoding="utf-8"))
    except OSError:
        return {}


def build_metadata(worktree: Path, profile: str) -> dict[str, str]:
    return read_marker(build_marker_path(worktree, profile))


def artifact_build_metadata(path: Path) -> dict[str, str]:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    worktree = next((parent for parent in resolved.parents if (parent / ".git").exists()), None)
    if worktree is None:
        return {}
    markers = sorted(worktree.glob(".agentic-build-*/.agentic-build.marker"))
    for marker in markers:
        metadata = read_marker(marker)
        if metadata.get("adapter") != ADAPTER_VERSION:
            continue
        return metadata
    return {}


def expected_elf(path: Path, architecture: str = "") -> bool:
    if not is_elf(path):
        return False
    return not architecture or matches_elf_architecture(path, architecture)


def has_regular_symbol_table(path: Path, nm: str = "nm") -> bool:
    try:
        proc = subprocess.run(
            [nm, "-A", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return proc.returncode == 0 and bool(proc.stdout.strip())


def has_libbfd_artifact(
    worktree: Path,
    profile: str,
    architecture: str = "",
    roots: list[Path] | None = None,
) -> bool:
    shared = profile_kind(profile) == "shared"
    for root in roots if roots is not None else candidate_roots(worktree, profile):
        bfd_dir = root / "bfd"
        if shared:
            for path in bfd_dir.glob(".libs/libbfd.so*"):
                if path.is_file() and not path.is_symlink() and expected_elf(path, architecture):
                    return True
            continue
        for path in (bfd_dir / ".libs" / "libbfd.a", bfd_dir / "libbfd.a"):
            if path.is_file() and path.stat().st_size > 0:
                return True
    return False


def has_built_binutils(
    worktree: Path,
    profile: str,
    config: BuildConfig | None = None,
    *,
    require_marker: bool = True,
    build_root: Path | None = None,
) -> bool:
    architecture = config.architecture if config is not None else build_metadata(worktree, profile).get("architecture", "")
    roots = [build_root] if build_root is not None else None
    candidates = candidates_for_binary(worktree, profile=profile, architecture=architecture, roots=roots)
    names = {name for _, name in candidates}
    built = has_libbfd_artifact(worktree, profile, architecture, roots=roots) and bool(
        names & {"readelf", "objdump", "c++filt"}
    )
    if not built or config is None or not require_marker:
        return built
    return has_build_marker(worktree, profile, config)


def configure_commands(config: BuildConfig, worktree: Path, profile: str) -> list[list[str]]:
    shared = profile_kind(profile) == "shared"
    src_configure = str(worktree / "configure")
    linkage = ["--enable-shared", "--disable-static"] if shared else ["--disable-shared", "--enable-static"]
    host = [f"--host={config.toolchain.configure_host}"] if config.architecture == "aarch64" else []
    base = [
        src_configure,
        *host,
        *linkage,
        "--enable-targets=all",
        "--disable-gdb",
        "--disable-gdbserver",
        "--disable-sim",
        "--disable-gas",
        "--disable-gprofng",
        "--disable-gold",
        "--disable-werror",
        "--disable-nls",
        "--without-debuginfod",
        "--without-guile",
        "--without-system-zlib",
        "--with-system-readline=no",
    ]
    compact = [
        src_configure,
        *host,
        *linkage,
        "--enable-targets=all",
        "--disable-gdb",
        "--disable-gdbserver",
        "--disable-sim",
        "--disable-werror",
        "--disable-nls",
    ]
    minimal = [
        src_configure,
        *host,
        *linkage,
        "--enable-targets=all",
        "--disable-gdb",
        "--disable-gdbserver",
        "--disable-sim",
        "--disable-gas",
        "--disable-gprofng",
        "--disable-gold",
        "--disable-werror",
        "--disable-nls",
    ]
    if shared:
        return [base, compact, minimal]
    return [base, compact, minimal]


def make_commands(build: Path) -> list[list[str]]:
    jobs = str(max(1, os.cpu_count() or 1))
    commands: list[list[str]] = []
    for target in ("all-bfd", "all-opcodes", "all-libiberty", "all-binutils", "all-ld"):
        commands.append(["make", "-j", jobs, "MAKEINFO=true", "TEXI2DVI=true", target])
    return commands


def clean_build_dir(build: Path) -> None:
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True, exist_ok=True)


def patch_disabled_gdb_prerequisite_check(worktree: Path, log: StageLogger) -> bool:
    configure = worktree / "configure"
    try:
        text = configure.read_text(encoding="utf-8")
    except OSError as exc:
        log.error("cannot read binutils configure for compatibility patch", path=str(configure), error=str(exc))
        return False
    if GDB_GMP_CHECK_WITH_DISABLE in text or GDB_GMP_CHECK not in text:
        return True
    try:
        configure.write_text(text.replace(GDB_GMP_CHECK, GDB_GMP_CHECK_WITH_DISABLE, 1), encoding="utf-8")
    except OSError as exc:
        log.error("cannot patch disabled GDB prerequisite check", path=str(configure), error=str(exc))
        return False
    log.trace("patched disabled GDB prerequisite check", path=str(configure))
    return True


def make_log_token(command: list[str]) -> str:
    tail = command[3:] if command[:3] == ["make", "-j", command[2] if len(command) > 2 else ""] else command[1:]
    token = "-".join(tail or ["all"])
    return re.sub(r"[^A-Za-z0-9.+-]+", "-", token).strip("-") or "all"


def compile_commit(config: BuildConfig, ref: str, stage: str, log: StageLogger, profile: str = "static") -> BuildOutput:
    worktree = ensure_worktree(config, ref, log, profile=profile)
    if worktree is None:
        return BuildOutput(commit=ref, worktree=Path(), ok=False, log_paths=[], notes="worktree setup failed")
    commit = subprocess.run(
        ["git", "-C", str(worktree), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
    log_paths: list[str] = []
    if has_built_binutils(worktree, profile, config):
        log.trace("reuse built binutils worktree", commit=commit, profile=profile, worktree=str(worktree))
        return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths, notes="reused existing build")
    if not patch_disabled_gdb_prerequisite_check(worktree, log):
        return BuildOutput(
            commit=commit,
            worktree=worktree,
            ok=False,
            log_paths=log_paths,
            notes="disabled GDB prerequisite compatibility patch failed",
        )

    build_log_dir = current_log_root(config.output) / "trace" / f"{stage}_builds"
    env = build_env(config)
    for index, configure in enumerate(configure_commands(config, worktree, profile), start=1):
        build = build_dir(worktree, f"{profile}-{index}")
        clean_build_dir(build)
        configure_log = build_log_dir / f"{commit[:12]}-{profile_kind(profile)}-config-{index}.log"
        result = run_command(configure, cwd=build, log_path=configure_log, env=env)
        log_paths.append(str(configure_log))
        if not result.ok:
            log.warn("binutils configure failed", commit=commit, profile=profile, command=configure, log=str(configure_log))
            continue
        ok = False
        for make_index, make in enumerate(make_commands(build), start=1):
            make_log = build_log_dir / f"{commit[:12]}-{profile_kind(profile)}-{index}-{make_index}-{make_log_token(make)}.log"
            result = run_command(make, cwd=build, log_path=make_log, env=env)
            log_paths.append(str(make_log))
            if has_built_binutils(worktree, profile, config, require_marker=False, build_root=build):
                if not result.ok:
                    log.warn(
                        "binutils make returned nonzero after producing ELF candidates",
                        commit=commit,
                        profile=profile,
                        command=make,
                        log=str(make_log),
                    )
                ok = True
                break
            if not result.ok:
                log.warn("binutils make failed", commit=commit, profile=profile, command=make, log=str(make_log))
        if ok:
            write_build_marker(config, worktree, profile, build)
            log.trace("binutils commit built", commit=commit, profile=profile, worktree=str(worktree), logs=log_paths)
            remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} build completed")
            return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths)
    return BuildOutput(commit=commit, worktree=worktree, ok=False, log_paths=log_paths, notes="all configure/build commands failed")


def candidate_roots(worktree: Path, profile: str = "static") -> list[Path]:
    recorded_name = build_metadata(worktree, profile).get("build_dir", "")
    if recorded_name.startswith(".agentic-build-") and Path(recorded_name).name == recorded_name:
        recorded = worktree / recorded_name
        if recorded.is_dir():
            return [recorded, worktree]
    roots = [build_dir(worktree, f"{profile}-{idx}") for idx in range(1, 5)]
    roots.append(build_dir(worktree, profile))
    roots.append(worktree)
    return [root for root in roots if root.exists()]


def canonical_binary_name(path: Path) -> str:
    name = path.name
    if name in {"nm-new", "nm"}:
        return "nm"
    if name in {"ld-new", "ld"}:
        return "ld"
    if name in {"cxxfilt", "c++filt"}:
        return "c++filt"
    if name.startswith("libbfd") and ".so" in name:
        return "libbfd"
    if name.startswith("libopcodes") and ".so" in name:
        return "libopcodes"
    if name.startswith("libctf") and ".so" in name:
        return "libctf"
    return name


def preferred_candidate_paths(root: Path) -> list[Path]:
    rels = [
        "binutils/readelf",
        "binutils/.libs/readelf",
        "binutils/objdump",
        "binutils/.libs/objdump",
        "binutils/nm-new",
        "binutils/.libs/nm-new",
        "binutils/cxxfilt",
        "binutils/.libs/cxxfilt",
        "binutils/c++filt",
        "binutils/.libs/c++filt",
        "ld/ld-new",
        "ld/.libs/ld-new",
        "bfd/libbfd.a",
        "bfd/.libs/libbfd.a",
        "bfd/.libs/libbfd.so",
        "bfd/.libs/libbfd.so.0",
        "opcodes/.libs/libopcodes.so",
        "libctf/.libs/libctf.so",
    ]
    paths = [root / rel for rel in rels]
    for directory in (root / "bfd" / ".libs", root / "opcodes" / ".libs", root / "libctf" / ".libs"):
        if directory.exists():
            paths.extend(sorted(directory.glob("*.so*")))
    return paths


def candidates_for_binary(
    worktree: Path,
    profile: str = "static",
    architecture: str = "",
    roots: list[Path] | None = None,
) -> list[tuple[Path, str]]:
    nm = build_metadata(worktree, profile).get("nm", "") or "nm"
    seen: set[Path] = set()
    found: list[tuple[Path, str]] = []
    for root in roots if roots is not None else candidate_roots(worktree, profile):
        paths = preferred_candidate_paths(root)
        for directory in (root / "binutils", root / "binutils" / ".libs", root / "ld", root / "ld" / ".libs"):
            if directory.exists():
                paths.extend(sorted(directory.iterdir()))
        for path in paths:
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if (
                resolved in seen
                or not path.is_file()
                or path.is_symlink()
                or not expected_elf(path, architecture)
                or not has_regular_symbol_table(path, nm)
            ):
                continue
            seen.add(resolved)
            found.append((path, canonical_binary_name(path)))
    return found


def choose_binary(worktree: Path, functions: list[str], preferred: str = "", profile: str = "static") -> BinaryMatch | None:
    metadata = build_metadata(worktree, profile)
    architecture = metadata.get("architecture", "")
    nm = metadata.get("nm", "")
    if architecture == "aarch64" and not nm:
        return None
    candidates = candidates_for_binary(worktree, profile=profile, architecture=architecture)
    if preferred:
        candidates = [item for item in candidates if item[1] == preferred] + [item for item in candidates if item[1] != preferred]
    best: BinaryMatch | None = None
    for path, name in candidates:
        names = symbol_names(path, nm=nm or "nm")
        missing = [fn for fn in functions if fn not in names]
        match = BinaryMatch(path=path, binary_name=name, missing=missing)
        if not missing:
            return match
        if best is None or len(missing) < len(best.missing):
            best = match
    return best


def find_binary_by_name(worktree: Path, binary_name: str, profile: str = "static") -> Path | None:
    architecture = build_metadata(worktree, profile).get("architecture", "")
    for path, name in candidates_for_binary(worktree, profile=profile, architecture=architecture):
        if name == binary_name:
            return path
    return None


def readelf_machine(path: Path, readelf: str) -> str:
    try:
        proc = subprocess.run(
            [readelf, "-hW", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except OSError:
        return ""
    if proc.returncode:
        return ""
    for line in proc.stdout.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == "Machine":
            return value.strip()
    return ""


def validate_copy_artifact(path: Path, metadata: dict[str, str]) -> bool:
    architecture = metadata.get("architecture") or elf_architecture(path)
    if architecture not in SUPPORTED_ARCHITECTURES or not matches_elf_architecture(path, architecture):
        return False
    readelf = metadata.get("readelf", "")
    if architecture == "aarch64" and not readelf:
        return False
    machine = readelf_machine(path, readelf or "readelf")
    if architecture == "aarch64":
        return machine == "AArch64"
    return "X86-64" in machine.upper() or "X86_64" in machine.upper()


def copy_binary(src: Path, dest: Path) -> None:
    src = Path(src)
    dest = Path(dest)
    metadata = artifact_build_metadata(src)
    if not validate_copy_artifact(src, metadata):
        try:
            if src.resolve() != dest.resolve():
                dest.unlink(missing_ok=True)
        except OSError:
            pass
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    dest.chmod(dest.stat().st_mode | 0o755)
    if not validate_copy_artifact(dest, metadata):
        dest.unlink(missing_ok=True)


def target_filename(project: str | BuildConfig, version: str, binary_name: str, compiler: str = "", opt: str = "") -> str:
    if isinstance(project, BuildConfig):
        return project.target_binary_name(version, binary_name)
    if compiler or opt:
        compiler_id = path_token(compiler, "compiler")
        opt_id = path_token(opt, "opt")
        return f"{project}-{version}-{binary_name}-{compiler_id}-{opt_id}"
    return f"{project}-{version}-{binary_name}"
