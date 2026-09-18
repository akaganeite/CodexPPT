from __future__ import annotations

import os
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

ADAPTER_VERSION = "libxml2-reference-20260909.1"
SUPPORTED_ARCHITECTURES = ("x86_64", "aarch64")
MAX_CONFIGURE_ATTEMPTS = 6


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
        with path.open("rb") as stream:
            header = stream.read(18)
        if len(header) < 18 or header[:4] != b"\x7fELF":
            return False
        byte_order = "<" if header[5] == 1 else ">"
        return struct.unpack(f"{byte_order}H", header[16:18])[0] in (2, 3)
    except OSError:
        return False


def symbol_names(path: Path, nm: str = "nm") -> set[str]:
    names: set[str] = set()
    for command in ([nm, "-A", str(path)], [nm, "-D", "-A", str(path)]):
        try:
            proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        except OSError:
            continue
        if proc.returncode:
            continue
        for line in proc.stdout.splitlines():
            parts = line.rsplit(None, 1)
            if len(parts) != 2:
                continue
            name = parts[1].split("@@", 1)[0].split("@", 1)[0]
            if name:
                names.add(name)
                names.add(name.lstrip("_"))
    return names


def build_token(config: BuildConfig, profile: str) -> str:
    return "-".join(
        (
            path_token(profile, "static"),
            path_token(config.build_variant, "variant"),
            path_token(ADAPTER_VERSION, "adapter"),
        )
    )


def resolve_commit(repo: Path, ref: str, log: StageLogger) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{ref}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode:
        log.error("cannot resolve libxml2 ref", ref=ref, stderr=proc.stderr.strip())
        return None
    return proc.stdout.strip()


def ensure_worktree(config: BuildConfig, ref: str, log: StageLogger, profile: str) -> Path | None:
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
        log.warn("libxml2 worktree path exists but is not reusable", ref=ref, path=str(worktree))
        return None
    add = subprocess.run(
        ["git", "-C", str(config.repo), "worktree", "add", "--detach", str(worktree), commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if add.returncode:
        log.error("failed to create libxml2 worktree", ref=ref, path=str(worktree), stderr=add.stderr.strip())
        return None
    return worktree


def build_dir(worktree: Path, profile: str, attempt: int) -> Path:
    return worktree / f".agentic-build-{path_token(profile, 'static')}-{attempt}"


def marker_path(worktree: Path, profile: str) -> Path:
    return worktree / f".agentic-build-{path_token(profile, 'static')}.marker"


def build_signature(config: BuildConfig, profile: str) -> str:
    toolchain = config.toolchain
    return (
        f"adapter={ADAPTER_VERSION}\n"
        f"architecture={config.architecture}\n"
        f"compiler={config.compiler}\n"
        f"opt={config.opt}\n"
        f"profile={profile}\n"
        f"triple={toolchain.triple}\n"
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


def has_build_marker(config: BuildConfig, worktree: Path, profile: str) -> bool:
    metadata = read_marker(marker_path(worktree, profile))
    expected = parse_marker(build_signature(config, profile))
    if not metadata or any(metadata.get(key) != value for key, value in expected.items()):
        return False
    build_name = metadata.get("build_dir", "")
    build = worktree / build_name
    try:
        return bool(build_name) and build.parent.resolve() == worktree.resolve() and build.is_dir()
    except OSError:
        return False


def write_build_marker(config: BuildConfig, worktree: Path, profile: str, build: Path) -> None:
    if build.parent.resolve() != worktree.resolve():
        raise ValueError(f"libxml2 build directory is outside its worktree: {build}")
    marker_path(worktree, profile).write_text(
        f"{build_signature(config, profile)}build_dir={build.name}\n",
        encoding="utf-8",
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
    return read_marker(marker_path(worktree, profile))


def artifact_build_metadata(path: Path) -> dict[str, str]:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    worktree = next((parent for parent in resolved.parents if (parent / ".git").exists()), None)
    if worktree is None:
        return {}
    for marker in sorted(worktree.glob(".agentic-build-*.marker")):
        metadata = read_marker(marker)
        if metadata.get("adapter") == ADAPTER_VERSION:
            return metadata
    return {}


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
        "-fno-inline",
        "-fno-omit-frame-pointer",
        "-Wno-error",
        "-Wno-error=implicit-function-declaration",
        "-Wno-error=incompatible-pointer-types",
        "-Wno-error=int-conversion",
    ]
    common_flags = " ".join(flag for flag in flags if flag)
    env["CFLAGS"] = common_flags
    env["CXXFLAGS"] = common_flags
    existing_ldflags = env.get("LDFLAGS", "").strip()
    toolchain_ldflags = " ".join(toolchain.compiler_flags)
    env["LDFLAGS"] = " ".join(part for part in (existing_ldflags, toolchain_ldflags) if part)
    env["MAKEINFO"] = "true"
    env["PYTHON"] = ":"
    aclocal_dirs = [path for path in ("/usr/share/aclocal", "/usr/share/pkgconfig/aclocal") if Path(path).is_dir()]
    existing_aclocal_path = env.get("ACLOCAL_PATH", "").strip()
    env["ACLOCAL_PATH"] = os.pathsep.join([*aclocal_dirs, *([existing_aclocal_path] if existing_aclocal_path else [])])
    if config.architecture == "aarch64":
        env["PKG_CONFIG"] = "false"
    return env


def configure_inputs_ready(worktree: Path) -> bool:
    return (worktree / "configure").is_file() and (worktree / "Makefile.in").is_file()


def configure_env(config: BuildConfig, worktree: Path) -> dict[str, str]:
    env = build_env(config)
    try:
        xz_source = (worktree / "xzlib.c").read_text(encoding="utf-8", errors="replace")
    except OSError:
        xz_source = ""
    if "#ifdef HAVE_LZMA_H" in xz_source:
        # Legacy pkg-config success skips the header probe gating all XZ code.
        # Use the compiler's real header/library checks, without forcing macros.
        env["PKG_CONFIG"] = "false"
    return env


def bootstrap_commands(worktree: Path) -> list[list[str]]:
    commands = [["libtoolize", "--force", "--copy"], ["autoreconf", "-fvi"]]
    if (worktree / "autogen.sh").exists():
        commands.append(["sh", "autogen.sh"])
    return commands


def configure_commands(config: BuildConfig, worktree: Path, profile: str) -> list[list[str]]:
    configure = str(worktree / "configure")
    linkage = ["--enable-shared", "--disable-static"] if profile == "shared" else ["--disable-shared", "--enable-static"]
    host = [f"--host={config.toolchain.configure_host}"] if config.architecture == "aarch64" else []
    base = [configure, *host, *linkage]
    common = ["--without-python", "--without-readline"]
    return [
        [*base, *common, "--with-lzma", "--with-zlib", "--without-icu"],
        [*base, *common, "--with-lzma", "--with-zlib"],
        [*base, *common, "--with-lzma"],
        [*base, *common, "--without-lzma", "--without-zlib", "--without-icu"],
        [*base, "--without-python", "--without-lzma", "--without-zlib"],
        [*base, "--without-python"],
    ]


def clean_build_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def jobs() -> str:
    return str(max(1, os.cpu_count() or 1))


def generate_configure(
    config: BuildConfig,
    worktree: Path,
    commit: str,
    stage: str,
    log: StageLogger,
    log_paths: list[str],
    successful_log_paths: list[str],
) -> bool:
    if configure_inputs_ready(worktree):
        return True
    log_dir = current_log_root(config.output) / "trace" / f"{stage}_builds"
    env = build_env(config)
    env["NOCONFIGURE"] = "1"
    for attempt, command in enumerate(bootstrap_commands(worktree), start=1):
        bootstrap_log = log_dir / f"{commit[:12]}-bootstrap-{attempt}.log"
        result = run_command(command, cwd=worktree, log_path=bootstrap_log, env=env)
        log_paths.append(str(bootstrap_log))
        if result.ok:
            successful_log_paths.append(str(bootstrap_log))
            if configure_inputs_ready(worktree):
                return True
        else:
            log.warn("libxml2 bootstrap failed", commit=commit, attempt=attempt, log=str(bootstrap_log))
    return False


def attempt_build(
    config: BuildConfig,
    worktree: Path,
    commit: str,
    stage: str,
    profile: str,
    log: StageLogger,
    log_paths: list[str],
    successful_log_paths: list[str],
) -> Path | None:
    if not generate_configure(config, worktree, commit, stage, log, log_paths, successful_log_paths):
        return None
    env = configure_env(config, worktree)
    log_dir = current_log_root(config.output) / "trace" / f"{stage}_builds"
    for attempt, configure in enumerate(configure_commands(config, worktree, profile), start=1):
        build = build_dir(worktree, profile, attempt)
        clean_build_dir(build)
        configure_log = log_dir / f"{commit[:12]}-{profile}-configure-{attempt}.log"
        configured = run_command(configure, cwd=build, log_path=configure_log, env=env)
        log_paths.append(str(configure_log))
        if not configured.ok:
            log.warn("libxml2 configure failed", commit=commit, attempt=attempt, log=str(configure_log))
            continue
        successful_log_paths.append(str(configure_log))
        make_commands = (
            ["make", "-j", jobs(), "xmllint", "xmlcatalog"],
            ["make", "-j", jobs(), "xmllint"],
            ["make", "-j", jobs()],
        )
        for make_attempt, make_command in enumerate(make_commands, start=1):
            make_log = log_dir / f"{commit[:12]}-{profile}-make-{attempt}-{make_attempt}.log"
            made = run_command(make_command, cwd=build, log_path=make_log, env=env)
            log_paths.append(str(make_log))
            if made.ok:
                successful_log_paths.append(str(make_log))
            if candidates_for_binary(
                worktree,
                profile,
                architecture=config.architecture,
                readelf=config.toolchain.readelf,
                roots=[build],
            ):
                if not made.ok:
                    log.warn("libxml2 make returned nonzero after producing ELF", log=str(make_log))
                return build
    return None


def candidate_roots(worktree: Path, profile: str) -> list[Path]:
    metadata = build_metadata(worktree, profile)
    build_name = metadata.get("build_dir", "") if metadata.get("adapter") == ADAPTER_VERSION else ""
    marked_build = worktree / build_name
    try:
        marked_build_ok = bool(build_name) and marked_build.parent.resolve() == worktree.resolve() and marked_build.is_dir()
    except OSError:
        marked_build_ok = False
    roots = [marked_build] if marked_build_ok else [
        build_dir(worktree, profile, attempt) for attempt in range(1, MAX_CONFIGURE_ATTEMPTS + 1)
    ]
    roots.append(worktree)
    return [root for root in roots if root.exists()]


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


def expected_elf(path: Path, architecture: str = "", readelf: str = "") -> bool:
    if not is_elf(path):
        return False
    if architecture and not matches_elf_architecture(path, architecture):
        return False
    if architecture == "aarch64":
        return bool(readelf) and readelf_machine(path, readelf) == "AArch64"
    return True


def candidates_for_binary(
    worktree: Path,
    profile: str = "static",
    architecture: str = "",
    readelf: str = "",
    roots: list[Path] | None = None,
) -> list[tuple[Path, str]]:
    found: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for root in roots if roots is not None else candidate_roots(worktree, profile):
        paths: list[tuple[Path, str]] = [
            (root / ".libs" / "xmllint", "xmllint"),
            (root / "xmllint", "xmllint"),
            (root / ".libs" / "xmlcatalog", "xmlcatalog"),
            (root / "xmlcatalog", "xmlcatalog"),
            (root / ".libs" / "libxml2.so", "libxml2"),
        ]
        if (root / ".libs").exists():
            paths.extend((path, "libxml2") for path in sorted((root / ".libs").glob("libxml2.so.*")))
        for path, name in paths:
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen or not path.is_file() or path.is_symlink() or not expected_elf(path, architecture, readelf):
                continue
            seen.add(resolved)
            found.append((path, name))
    return found


def has_built_libxml2(config: BuildConfig, worktree: Path, profile: str) -> bool:
    return has_build_marker(config, worktree, profile) and bool(
        candidates_for_binary(
            worktree,
            profile,
            architecture=config.architecture,
            readelf=config.toolchain.readelf,
        )
    )


def compile_commit(config: BuildConfig, ref: str, stage: str, log: StageLogger, profile: str = "static") -> BuildOutput:
    if config.architecture not in SUPPORTED_ARCHITECTURES:
        return BuildOutput(
            commit=ref,
            worktree=Path(),
            ok=False,
            log_paths=[],
            notes=f"unsupported architecture: {config.architecture}",
        )
    worktree = ensure_worktree(config, ref, log, profile)
    if worktree is None:
        return BuildOutput(commit=ref, worktree=Path(), ok=False, log_paths=[], notes="worktree setup failed")
    commit = resolve_commit(config.repo, ref, log) or ref
    if has_built_libxml2(config, worktree, profile):
        return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=[], notes="reused existing build")

    log_paths: list[str] = []
    successful_log_paths: list[str] = []
    build = attempt_build(config, worktree, commit, stage, profile, log, log_paths, successful_log_paths)
    if build is not None:
        write_build_marker(config, worktree, profile, build)
        remove_build_logs(config, successful_log_paths, log, success=True, reason=f"{stage} successful libxml2 build")
        return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths, notes="built libxml2 tools")
    return BuildOutput(
        commit=commit,
        worktree=worktree,
        ok=False,
        log_paths=log_paths,
        notes="all libxml2 bootstrap/configure/build commands failed",
    )


def choose_binary(worktree: Path, functions: list[str], preferred: str = "", profile: str = "static") -> BinaryMatch | None:
    metadata = build_metadata(worktree, profile)
    architecture = metadata.get("architecture", "")
    nm = metadata.get("nm", "")
    readelf = metadata.get("readelf", "")
    if architecture == "aarch64" and (not nm or not readelf):
        return None
    candidates = candidates_for_binary(worktree, profile, architecture=architecture, readelf=readelf)
    if not candidates:
        return None
    if not architecture and any(elf_architecture(path) == "aarch64" for path, _ in candidates):
        return None
    wanted = [function for function in functions if function]
    best: BinaryMatch | None = None
    for path, name in candidates:
        names = symbol_names(path, nm=nm or "nm")
        missing = [function for function in wanted if function not in names and function.lstrip("_") not in names]
        match = BinaryMatch(path=path, binary_name=name, missing=missing)
        if preferred and preferred != name:
            continue
        if not missing:
            return match
        if best is None or len(missing) < len(best.missing):
            best = match
    if best is not None or not preferred:
        return best
    return choose_binary(worktree, functions, profile=profile)


def find_binary_by_name(worktree: Path, binary_name: str, profile: str = "static") -> Path | None:
    metadata = build_metadata(worktree, profile)
    architecture = metadata.get("architecture", "")
    readelf = metadata.get("readelf", "")
    if architecture == "aarch64" and not readelf:
        return None
    candidates = candidates_for_binary(worktree, profile, architecture=architecture, readelf=readelf)
    if not architecture and any(elf_architecture(path) == "aarch64" for path, _ in candidates):
        return None
    for path, name in candidates:
        if name == binary_name or (not binary_name and name == "xmllint"):
            return path
    return None


def validate_copy_artifact(path: Path, metadata: dict[str, str]) -> bool:
    architecture = metadata.get("architecture") or elf_architecture(path)
    if architecture not in SUPPORTED_ARCHITECTURES or not matches_elf_architecture(path, architecture):
        return False
    if architecture == "aarch64":
        readelf = metadata.get("readelf", "")
        return bool(readelf) and readelf_machine(path, readelf) == "AArch64"
    return True


def copy_binary(src: Path | str, dest: Path | str) -> None:
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


def target_filename(
    project: str | BuildConfig,
    version: str,
    binary_name: str,
    compiler: str = "",
    opt: str = "",
) -> str:
    if isinstance(project, BuildConfig):
        return project.target_binary_name(version, binary_name)
    if compiler or opt:
        return f"{project}-{version}-{binary_name}-{path_token(compiler, 'compiler')}-{path_token(opt, 'opt')}"
    return f"{project}-{version}-{binary_name}"
