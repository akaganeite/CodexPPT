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

ADAPTER_VERSION = "sqlite-reference-20260813.1"
SUPPORTED_ARCHITECTURES = ("x86_64", "aarch64")
MAX_CONFIGURE_ATTEMPTS = 4


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
        log.error("cannot resolve sqlite ref", ref=ref, stderr=proc.stderr.strip())
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
        log.warn("sqlite worktree path exists but is not reusable", ref=ref, path=str(worktree))
        return None
    add = subprocess.run(
        ["git", "-C", str(config.repo), "worktree", "add", "--detach", str(worktree), commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if add.returncode:
        log.error("failed to create sqlite worktree", ref=ref, path=str(worktree), stderr=add.stderr.strip())
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
        raise ValueError(f"sqlite build directory is outside its worktree: {build}")
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
    if config.architecture == "aarch64":
        env["PKG_CONFIG"] = "false"
    return env


def configure_optional_flags(worktree: Path) -> list[str]:
    try:
        configure_text = (worktree / "configure").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return ["--disable-tcl"] if "--disable-tcl" in configure_text else []


def configure_commands(config: BuildConfig, worktree: Path) -> list[list[str]]:
    configure = str(worktree / "configure")
    host = [f"--host={config.toolchain.configure_host}"] if config.architecture == "aarch64" else []
    optional = configure_optional_flags(worktree) if config.architecture == "aarch64" else []
    return [
        [
            configure,
            *host,
            *optional,
            "--disable-shared",
            "--enable-static",
            "--disable-readline",
            "--enable-fts3",
            "--enable-fts4",
            "--enable-json1",
            "--enable-rtree",
        ],
        [configure, *host, *optional, "--disable-shared", "--enable-static", "--disable-readline"],
        [configure, *host, *optional, "--disable-shared", "--enable-static"],
        [configure, *host, *optional],
    ]


def config_sub_accepts(config_sub: Path, host: str) -> bool:
    try:
        proc = subprocess.run(
            ["sh", str(config_sub), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return proc.returncode == 0


def replacement_config_sub() -> Path | None:
    candidates = [Path("/usr/share/misc/config.sub")]
    candidates.extend(sorted(Path("/usr/share").glob("automake-*/config.sub"), reverse=True))
    return next((path for path in candidates if path.is_file()), None)


def prepare_cross_configure(config: BuildConfig, worktree: Path, log: StageLogger) -> bool:
    if config.architecture != "aarch64":
        return True
    config_sub = worktree / "config.sub"
    if not config_sub.is_file():
        return True
    host = config.toolchain.configure_host
    if config_sub_accepts(config_sub, host):
        return True
    replacement = replacement_config_sub()
    if replacement is None:
        log.error("sqlite config.sub does not recognize AArch64 and no system replacement is available", path=str(config_sub))
        return False
    try:
        shutil.copy2(replacement, config_sub)
        config_sub.chmod(config_sub.stat().st_mode | 0o755)
    except OSError as exc:
        log.error("failed to refresh sqlite config.sub in detached worktree", path=str(config_sub), error=str(exc))
        return False
    if not config_sub_accepts(config_sub, host):
        log.error("replacement sqlite config.sub still rejects configured host", host=host, path=str(config_sub))
        return False
    log.trace("refreshed stale sqlite config.sub in detached worktree", host=host, source=str(replacement))
    return True


def clean_build_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def jobs() -> str:
    return str(max(1, os.cpu_count() or 1))


def generation_command(build: Path) -> list[str]:
    targets = ["sqlite3.c", "sqlite3.h"]
    # Newer SQLite releases generate an expanded shell; older releases build
    # directly from src/shell.c and do not define this target.
    for makefile in (build / "Makefile", build.parent / "main.mk"):
        try:
            lines = makefile.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if any(line.lstrip().startswith("shell.c:") for line in lines):
            targets.append("shell.c")
            break
    return ["make", "-j", jobs(), *targets]


def shell_source(worktree: Path, build: Path) -> Path | None:
    for candidate in (build / "shell.c", worktree / "src" / "shell.c"):
        if candidate.exists():
            return candidate
    return None


def profile_definitions(profile: str) -> list[str]:
    """Opt-in real reference features; ordinary target profiles stay unchanged."""
    tokens = set(profile.lower().split("-"))
    definitions: list[str] = []
    if "debug" in tokens:
        definitions.append("-DSQLITE_DEBUG")
    if "fts5" in tokens:
        definitions.append("-DSQLITE_ENABLE_FTS5")
    if "session" in tokens:
        definitions.extend(["-DSQLITE_ENABLE_SESSION", "-DSQLITE_ENABLE_PREUPDATE_HOOK"])
    if "explain-comments" in profile.lower():
        definitions.append("-DSQLITE_ENABLE_EXPLAIN_COMMENTS")
    return definitions


def direct_compile_command(config: BuildConfig, worktree: Path, build: Path, profile: str = "") -> list[str] | None:
    shell = shell_source(worktree, build)
    amalgamation = build / "sqlite3.c"
    if shell is None or not amalgamation.exists():
        return None
    definitions = [
        "-DSQLITE_ENABLE_FTS3",
        "-DSQLITE_ENABLE_FTS4",
        "-DSQLITE_ENABLE_RTREE",
        "-DSQLITE_ENABLE_JSON1",
    ]
    definitions.extend(profile_definitions(profile))
    flags = [
        *config.toolchain.compiler_flags,
        "-g3",
        config.opt.strip(),
        "-fcommon",
        "-fno-inline",
        "-fno-omit-frame-pointer",
        "-Wno-error",
    ]
    return [
        config.toolchain.c_compiler,
        *(flag for flag in flags if flag),
        *definitions,
        "-I",
        str(build),
        "-I",
        str(worktree),
        "-o",
        str(build / "agentic-sqlite3"),
        str(shell),
        str(amalgamation),
        "-ldl",
        "-lpthread",
        "-lm",
    ]


def attempt_build(
    config: BuildConfig,
    worktree: Path,
    commit: str,
    stage: str,
    profile: str,
    log: StageLogger,
    log_paths: list[str],
) -> Path | None:
    env = build_env(config)
    feature_flags = profile_definitions(profile)
    if feature_flags:
        env["CPPFLAGS"] = " ".join([env.get("CPPFLAGS", ""), *feature_flags]).strip()
    log_dir = current_log_root(config.output) / "trace" / f"{stage}_builds"
    if not prepare_cross_configure(config, worktree, log):
        return None
    for attempt, configure in enumerate(configure_commands(config, worktree), start=1):
        build = build_dir(worktree, profile, attempt)
        clean_build_dir(build)
        configure_log = log_dir / f"{commit[:12]}-{profile}-configure-{attempt}.log"
        configured = run_command(configure, cwd=build, log_path=configure_log, env=env)
        log_paths.append(str(configure_log))
        if not configured.ok:
            log.warn("sqlite configure failed", commit=commit, attempt=attempt, log=str(configure_log))
            continue

        generate_log = log_dir / f"{commit[:12]}-{profile}-generate-{attempt}.log"
        generated = run_command(generation_command(build), cwd=build, log_path=generate_log, env=env)
        log_paths.append(str(generate_log))
        direct = direct_compile_command(config, worktree, build, profile)
        if generated.ok and direct is not None:
            compile_log = log_dir / f"{commit[:12]}-{profile}-compile-{attempt}.log"
            compiled = run_command(direct, cwd=build, log_path=compile_log, env=env)
            log_paths.append(str(compile_log))
            if expected_elf(
                build / "agentic-sqlite3",
                architecture=config.architecture,
                readelf=config.toolchain.readelf,
            ):
                if not compiled.ok:
                    log.warn("sqlite direct compile returned nonzero after producing ELF", log=str(compile_log))
                return build

        make_log = log_dir / f"{commit[:12]}-{profile}-make-{attempt}.log"
        made = run_command(["make", "-j", jobs(), "sqlite3"], cwd=build, log_path=make_log, env=env)
        log_paths.append(str(make_log))
        if candidates_for_binary(
            worktree,
            profile,
            architecture=config.architecture,
            readelf=config.toolchain.readelf,
            roots=[build],
        ):
            if not made.ok:
                log.warn("sqlite make returned nonzero after producing ELF", log=str(make_log))
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
        paths = [
            root / "agentic-sqlite3",
            root / "sqlite3",
            root / ".libs" / "sqlite3",
            root / ".libs" / "libsqlite3.so",
        ]
        if (root / ".libs").exists():
            paths.extend(sorted((root / ".libs").glob("libsqlite3.so.*")))
        for path in paths:
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen or not path.is_file() or path.is_symlink() or not expected_elf(path, architecture, readelf):
                continue
            seen.add(resolved)
            found.append((path, "sqlite3"))
    return found


def has_built_sqlite(config: BuildConfig, worktree: Path, profile: str) -> bool:
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
    if has_built_sqlite(config, worktree, profile):
        return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=[], notes="reused existing build")

    log_paths: list[str] = []
    build = attempt_build(config, worktree, commit, stage, profile, log, log_paths)
    if build is not None:
        write_build_marker(config, worktree, profile, build)
        remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} successful sqlite build")
        return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths, notes="built sqlite3 amalgamation")
    return BuildOutput(
        commit=commit,
        worktree=worktree,
        ok=False,
        log_paths=log_paths,
        notes="all sqlite configure/build commands failed",
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
    if binary_name not in ("", "sqlite3"):
        return None
    metadata = build_metadata(worktree, profile)
    architecture = metadata.get("architecture", "")
    readelf = metadata.get("readelf", "")
    if architecture == "aarch64" and not readelf:
        return None
    candidates = candidates_for_binary(worktree, profile, architecture=architecture, readelf=readelf)
    if not architecture and any(elf_architecture(path) == "aarch64" for path, _ in candidates):
        return None
    return candidates[0][0] if candidates else None


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
        return (
            f"{project}-{version}-{binary_name}-"
            f"{path_token(compiler, 'compiler')}-{path_token(opt, 'opt')}"
        )
    return f"{project}-{version}-{binary_name}"
