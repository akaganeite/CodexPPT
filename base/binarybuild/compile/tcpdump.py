from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from binarybuild.build_log_cleanup import remove_build_logs
from builder.config import BuildConfig, path_token
from builder.logging import StageLogger, current_log_root
from utils.command import run_command

ADAPTER_VERSION = "tcpdump-reference-20260707.1"


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


def symbol_names(path: Path) -> set[str]:
    names: set[str] = set()
    for command in (["nm", "-A", str(path)], ["nm", "-D", "-A", str(path)]):
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
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
    return "cmake" if profile.startswith("cmake") else "autoconf"


def build_token(config: BuildConfig, profile: str) -> str:
    profile_id = path_token(profile, profile_kind(profile))
    compiler_id = path_token(config.compiler, "compiler")
    opt_id = path_token(config.opt, "opt")
    adapter_id = path_token(ADAPTER_VERSION, "adapter")
    return f"{profile_id}-{compiler_id}-{opt_id}-{adapter_id}"


def resolve_commit(repo: Path, ref: str, log: StageLogger) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{ref}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode:
        log.error("cannot resolve tcpdump ref", ref=ref, stderr=proc.stderr.strip())
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
        log.warn("tcpdump worktree path exists but is not reusable", ref=ref, path=str(worktree))
        return None
    add = subprocess.run(
        ["git", "-C", str(config.repo), "worktree", "add", "--detach", str(worktree), commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if add.returncode:
        log.error("failed to create tcpdump worktree", ref=ref, path=str(worktree), stderr=add.stderr.strip())
        return None
    return worktree


def append_env_flags(env: dict[str, str], name: str, flags: list[str]) -> None:
    existing = env.get(name, "").strip()
    addition = " ".join(flag for flag in flags if flag)
    env[name] = " ".join(part for part in (existing, addition) if part)


def build_env(config: BuildConfig) -> dict[str, str]:
    env = os.environ.copy()
    env["CC"] = config.compiler
    flags = [
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
    env["CFLAGS"] = " ".join(flag for flag in flags if flag)
    env["MAKEINFO"] = "true"
    env["YACC"] = env.get("YACC", "bison -y")
    append_env_flags(env, "LDFLAGS", ["-Wl,--no-as-needed"])
    return env


def build_dir(worktree: Path, profile: str) -> Path:
    return worktree / f".agentic-build-{path_token(profile, 'profile')}"


def build_marker_path(worktree: Path, profile: str) -> Path:
    return build_dir(worktree, profile) / ".agentic-build.marker"


def build_signature(config: BuildConfig, profile: str) -> str:
    return (
        f"adapter={ADAPTER_VERSION}\n"
        f"compiler={config.compiler}\n"
        f"opt={config.opt}\n"
        f"profile={profile}\n"
    )


def write_build_marker(config: BuildConfig, worktree: Path, profile: str) -> None:
    marker = build_marker_path(worktree, profile)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(build_signature(config, profile), encoding="utf-8")


def has_build_marker(worktree: Path, profile: str, config: BuildConfig) -> bool:
    try:
        return build_marker_path(worktree, profile).read_text(encoding="utf-8") == build_signature(config, profile)
    except OSError:
        return False


def clean_build_dir(build: Path) -> None:
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True, exist_ok=True)


def has_built_tcpdump(worktree: Path, profile: str, config: BuildConfig | None = None) -> bool:
    built = any(name == "tcpdump" for _, name in candidates_for_binary(worktree, profile=profile))
    if not built or config is None:
        return built
    return has_build_marker(worktree, profile, config)


def ensure_configure(worktree: Path, env: dict[str, str], log_path: Path) -> bool:
    if (worktree / "configure").exists():
        return True
    autogen = worktree / "autogen.sh"
    if autogen.exists():
        result = run_command(["sh", str(autogen)], cwd=worktree, log_path=log_path, env=env)
        return result.ok and (worktree / "configure").exists()
    return False


def autoconf_configure_commands(worktree: Path) -> list[list[str]]:
    configure = str(worktree / "configure")
    return [
        [
            configure,
            "--with-system-libpcap",
            "--without-crypto",
            "--enable-smb",
            "--disable-universal",
        ],
        [configure, "--with-system-libpcap", "--enable-smb", "--disable-universal"],
        [configure, "--with-system-libpcap", "--without-crypto"],
        [configure, "--with-system-libpcap"],
        [configure],
    ]


def cmake_configure_commands(config: BuildConfig, worktree: Path, build: Path) -> list[list[str]]:
    return [
        [
            "cmake",
            "-S",
            str(worktree),
            "-B",
            str(build),
            "-DCMAKE_BUILD_TYPE=Debug",
            f"-DCMAKE_C_COMPILER={config.compiler}",
            "-DENABLE_SMB=ON",
            "-DWITH_CRYPTO=OFF",
        ],
        [
            "cmake",
            "-S",
            str(worktree),
            "-B",
            str(build),
            "-DCMAKE_BUILD_TYPE=Debug",
            f"-DCMAKE_C_COMPILER={config.compiler}",
        ],
    ]


def jobs() -> str:
    return str(max(1, os.cpu_count() or 1))


def make_log_token(command: list[str]) -> str:
    token = "-".join(command[1:] or ["all"])
    return re.sub(r"[^A-Za-z0-9.+-]+", "-", token).strip("-") or "all"


def try_autoconf_build(
    config: BuildConfig,
    worktree: Path,
    commit: str,
    stage: str,
    log: StageLogger,
    profile: str,
    log_paths: list[str],
) -> bool:
    build_log_dir = current_log_root(config.output) / "trace" / f"{stage}_builds"
    env = build_env(config)
    autogen_log = build_log_dir / f"{commit[:12]}-{profile}-autogen.log"
    if not ensure_configure(worktree, env, autogen_log):
        if autogen_log.exists():
            log_paths.append(str(autogen_log))
        log.warn("tcpdump configure script unavailable", commit=commit, profile=profile, log=str(autogen_log))
        return False
    if autogen_log.exists():
        log_paths.append(str(autogen_log))

    for index, configure in enumerate(autoconf_configure_commands(worktree), start=1):
        build = build_dir(worktree, f"{profile}-autoconf-{index}")
        clean_build_dir(build)
        configure_log = build_log_dir / f"{commit[:12]}-{profile}-autoconf-config-{index}.log"
        result = run_command(configure, cwd=build, log_path=configure_log, env=env)
        log_paths.append(str(configure_log))
        if not result.ok:
            log.warn("tcpdump autoconf configure failed", commit=commit, command=configure, log=str(configure_log))
            continue
        for make_index, make in enumerate((["make", "-j", jobs(), "tcpdump"], ["make", "-j", jobs()]), start=1):
            make_log = build_log_dir / f"{commit[:12]}-{profile}-autoconf-{index}-{make_index}-{make_log_token(make)}.log"
            result = run_command(make, cwd=build, log_path=make_log, env=env)
            log_paths.append(str(make_log))
            if has_built_tcpdump(worktree, profile):
                if not result.ok:
                    log.warn(
                        "tcpdump make returned nonzero after producing tcpdump ELF",
                        commit=commit,
                        command=make,
                        log=str(make_log),
                    )
                return True
            if not result.ok:
                log.warn("tcpdump make failed", commit=commit, command=make, log=str(make_log))
    return False


def try_cmake_build(
    config: BuildConfig,
    worktree: Path,
    commit: str,
    stage: str,
    log: StageLogger,
    profile: str,
    log_paths: list[str],
) -> bool:
    if not (worktree / "CMakeLists.txt").exists():
        return False
    build_log_dir = current_log_root(config.output) / "trace" / f"{stage}_builds"
    env = build_env(config)
    append_env_flags(env, "CMAKE_C_FLAGS", [env.get("CFLAGS", "")])
    for index in range(1, 3):
        build = build_dir(worktree, f"{profile}-cmake-{index}")
        clean_build_dir(build)
        configure = cmake_configure_commands(config, worktree, build)[index - 1]
        configure_log = build_log_dir / f"{commit[:12]}-{profile}-cmake-config-{index}.log"
        result = run_command(configure, cwd=build, log_path=configure_log, env=env)
        log_paths.append(str(configure_log))
        if not result.ok:
            log.warn("tcpdump cmake configure failed", commit=commit, command=configure, log=str(configure_log))
            continue
        make = ["cmake", "--build", str(build), "--target", "tcpdump", "--", "-j", jobs()]
        make_log = build_log_dir / f"{commit[:12]}-{profile}-cmake-{index}-build.log"
        result = run_command(make, cwd=build, log_path=make_log, env=env)
        log_paths.append(str(make_log))
        if has_built_tcpdump(worktree, profile):
            if not result.ok:
                log.warn(
                    "tcpdump cmake build returned nonzero after producing tcpdump ELF",
                    commit=commit,
                    command=make,
                    log=str(make_log),
                )
            return True
        if not result.ok:
            log.warn("tcpdump cmake build failed", commit=commit, command=make, log=str(make_log))
    return False


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
    if has_built_tcpdump(worktree, profile, config):
        log.trace("reuse built tcpdump worktree", commit=commit, profile=profile, worktree=str(worktree))
        return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths, notes="reused existing build")

    build_log_dir = current_log_root(config.output) / "trace" / f"{stage}_builds"
    build_log_dir.mkdir(parents=True, exist_ok=True)
    attempts = (
        (try_autoconf_build, "autoconf"),
        (try_cmake_build, "cmake"),
    )
    if profile.startswith("cmake"):
        attempts = tuple(reversed(attempts))
    for build_func, name in attempts:
        if build_func(config, worktree, commit, stage, log, profile, log_paths):
            write_build_marker(config, worktree, profile)
            log.trace("tcpdump commit built", commit=commit, profile=profile, method=name, worktree=str(worktree), logs=log_paths)
            remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} build completed")
            return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths, notes=f"built with {name}")
    return BuildOutput(commit=commit, worktree=worktree, ok=False, log_paths=log_paths, notes="all configure/build commands failed")


def candidate_roots(worktree: Path, profile: str = "static") -> list[Path]:
    roots = [build_dir(worktree, f"{profile}-autoconf-{idx}") for idx in range(1, 6)]
    roots.extend(build_dir(worktree, f"{profile}-cmake-{idx}") for idx in range(1, 4))
    roots.append(build_dir(worktree, profile))
    roots.append(worktree)
    return [root for root in roots if root.exists()]


def canonical_binary_name(path: Path) -> str:
    if path.name == "tcpdump":
        return "tcpdump"
    return path.name


def preferred_candidate_paths(root: Path) -> list[Path]:
    return [
        root / "tcpdump",
        root / ".libs" / "tcpdump",
        root / "src" / "tcpdump",
    ]


def candidates_for_binary(worktree: Path, profile: str = "static") -> list[tuple[Path, str]]:
    seen: set[Path] = set()
    found: list[tuple[Path, str]] = []
    for root in candidate_roots(worktree, profile):
        paths = preferred_candidate_paths(root)
        for directory in (root, root / ".libs", root / "src"):
            if directory.exists():
                paths.extend(sorted(directory.iterdir()))
        for path in paths:
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen or not path.is_file() or path.is_symlink() or not is_elf(path):
                continue
            seen.add(resolved)
            found.append((path, canonical_binary_name(path)))
    return found


def choose_binary(worktree: Path, functions: list[str], preferred: str = "", profile: str = "static") -> BinaryMatch | None:
    candidates = candidates_for_binary(worktree, profile=profile)
    if preferred:
        candidates = [item for item in candidates if item[1] == preferred] + [item for item in candidates if item[1] != preferred]
    best: BinaryMatch | None = None
    for path, name in candidates:
        names = symbol_names(path)
        missing = [fn for fn in functions if fn not in names]
        match = BinaryMatch(path=path, binary_name=name, missing=missing)
        if not missing:
            return match
        if best is None or len(missing) < len(best.missing):
            best = match
    return best


def find_binary_by_name(worktree: Path, binary_name: str, profile: str = "static") -> Path | None:
    for path, name in candidates_for_binary(worktree, profile=profile):
        if name == binary_name:
            return path
    return None


def copy_binary(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    dest.chmod(dest.stat().st_mode | 0o755)


def target_filename(project: str, version: str, binary_name: str, compiler: str = "", opt: str = "") -> str:
    if compiler or opt:
        compiler_id = path_token(compiler, "compiler")
        opt_id = path_token(opt, "opt")
        return f"{project}-{version}-{binary_name}-{compiler_id}-{opt_id}"
    return f"{project}-{version}-{binary_name}"
