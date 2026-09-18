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

ADAPTER_VERSION = "ffmpeg-reference-20260812.3"
SUPPORTED_ARCHITECTURES = ("x86_64", "aarch64")


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
            if name:
                names.add(name)
                names.add(name.lstrip("_"))
    return names


def build_token(config: BuildConfig, profile: str) -> str:
    profile_id = path_token(profile, "static")
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
        log.error("cannot resolve ffmpeg ref", ref=ref, stderr=proc.stderr.strip())
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
        log.warn("ffmpeg worktree path exists but is not reusable", ref=ref, path=str(worktree))
        return None
    proc = subprocess.run(
        ["git", "-C", str(config.repo), "worktree", "add", "--detach", str(worktree), commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode:
        log.error("failed to create ffmpeg worktree", ref=ref, path=str(worktree), stderr=proc.stderr.strip())
        return None
    return worktree


def build_dir(worktree: Path, profile: str) -> Path:
    return worktree / f".agentic-build-{path_token(profile, 'profile')}"


def build_cwd(worktree: Path, profile: str) -> Path:
    # FFmpeg out-of-tree configure creates a "src" symlink, which is not
    # supported on some dataset filesystems. Detached worktrees are disposable,
    # so build in-tree while keeping adapter markers under .agentic-build-*.
    return worktree


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


def has_build_marker(worktree: Path, profile: str, config: BuildConfig) -> bool:
    try:
        return build_marker_path(worktree, profile).read_text(encoding="utf-8") == build_signature(config, profile)
    except OSError:
        return False


def write_build_marker(config: BuildConfig, worktree: Path, profile: str) -> None:
    marker = build_marker_path(worktree, profile)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(build_signature(config, profile), encoding="utf-8")


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
    for marker in sorted(worktree.glob(".agentic-build-*/.agentic-build.marker")):
        metadata = read_marker(marker)
        if metadata.get("adapter") == ADAPTER_VERSION:
            return metadata
    return {}


def clean_build_dir(build: Path) -> None:
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True, exist_ok=True)


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
            "AS": toolchain.c_compiler,
            "LD": toolchain.c_compiler,
        }
    )
    flags = [*toolchain.compiler_flags, "-g3", config.opt.strip(), "-fcommon", "-Wno-error"]
    common_flags = " ".join(flag for flag in flags if flag)
    env["CFLAGS"] = common_flags
    env["CXXFLAGS"] = common_flags
    link_flags = [*toolchain.compiler_flags, "-Wl,--no-as-needed"]
    env["LDFLAGS"] = " ".join(
        part for part in (env.get("LDFLAGS", "").strip(), " ".join(link_flags)) if part
    )
    if config.architecture == "aarch64":
        env["PKG_CONFIG"] = "false"
    env["MAKEINFO"] = "true"
    return env


def configure_tool_args(config: BuildConfig) -> list[str]:
    toolchain = config.toolchain
    args = [
        f"--cc={toolchain.c_compiler}",
        f"--cxx={toolchain.cxx_compiler}",
        f"--ar={toolchain.ar}",
        f"--ranlib={toolchain.ranlib}",
        f"--nm={toolchain.nm}",
        f"--strip={toolchain.strip}",
        f"--as={toolchain.c_compiler}",
        f"--ld={toolchain.c_compiler}",
        f"--objcc={toolchain.c_compiler}",
        f"--dep-cc={toolchain.c_compiler}",
    ]
    if toolchain.compiler_flags:
        compiler_flags = " ".join(toolchain.compiler_flags)
        args.extend(
            [
                f"--extra-cflags={compiler_flags}",
                f"--extra-cxxflags={compiler_flags}",
                f"--extra-ldflags={compiler_flags}",
            ]
        )
    if config.architecture == "aarch64":
        args = [
            "--enable-cross-compile",
            "--arch=aarch64",
            "--target-os=linux",
            f"--cross-prefix={toolchain.configure_host}-",
            "--pkg-config=false",
            *args,
        ]
    return args


def configure_commands(config: BuildConfig, worktree: Path, profile: str) -> list[list[str]]:
    configure = str(worktree / "configure")
    library_flags = ["--disable-shared", "--enable-static"]
    component_flags: list[str] = []
    if "exr-zlib" in profile.lower():
        component_flags = ["--enable-zlib", "--enable-decoder=exr"]
    common = [
        "--enable-debug=3",
        "--disable-stripping",
        *library_flags,
        *component_flags,
        f"--optflags={config.opt.strip()}",
        *configure_tool_args(config),
    ]
    doc_flags = ["--disable-doc", "--disable-htmlpages", "--disable-manpages", "--disable-podpages", "--disable-txtpages"]
    if config.architecture == "aarch64":
        return [
            [configure, *common, "--disable-asm", *doc_flags],
            [configure, *common, "--disable-asm"],
            [configure, *common, "--disable-autodetect", "--disable-asm", *doc_flags],
            [configure, *common, "--disable-autodetect", "--disable-asm"],
            [configure, *common, "--disable-autodetect"],
            [configure, *common],
        ]
    return [
        [configure, *common, "--disable-asm", *doc_flags],
        [configure, *common, "--disable-x86asm", *doc_flags],
        [configure, *common, "--disable-asm"],
        [configure, *common],
    ]


def clean_in_tree_config(worktree: Path) -> None:
    if not (worktree / "config.mak").exists():
        return
    subprocess.run(["make", "distclean"], cwd=worktree, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def enable_profile_components(worktree: Path, profile: str, log: StageLogger) -> bool:
    normalized = profile.lower()
    if "cbs-jpeg" not in normalized and "exr-zlib" not in normalized:
        return True
    make_config = worktree / "ffbuild" / "config.mak"
    header = worktree / "config.h"
    if not make_config.is_file() or not header.is_file():
        log.warn("ffmpeg profile component config is missing", profile=profile, worktree=str(worktree))
        return False

    make_text = make_config.read_text(encoding="utf-8", errors="replace")
    header_text = header.read_text(encoding="utf-8", errors="replace")
    if "cbs-jpeg" in normalized:
        for component in ("CONFIG_CBS", "CONFIG_CBS_JPEG"):
            make_text = re.sub(rf"^!?{component}=(?:yes|no)$", f"{component}=yes", make_text, flags=re.MULTILINE)
            if f"{component}=yes" not in make_text:
                make_text += f"\n{component}=yes\n"
            header_text = re.sub(rf"^#define {component} [01]$", f"#define {component} 1", header_text, flags=re.MULTILINE)
            if f"#define {component} 1" not in header_text:
                header_text += f"\n#define {component} 1\n"
        make_config.write_text(make_text, encoding="utf-8")
        header.write_text(header_text, encoding="utf-8")
        log.trace("enabled ffmpeg profile components", profile=profile, components=["cbs", "cbs_jpeg"])
    if "exr-zlib" in normalized:
        required = ("CONFIG_ZLIB", "CONFIG_EXR_DECODER")
        missing = [component for component in required if f"#define {component} 1" not in header_text]
        if missing:
            log.warn("ffmpeg EXR profile dependencies are unavailable", profile=profile, missing=missing)
            return False
        log.trace("validated ffmpeg profile components", profile=profile, components=["zlib", "exr_decoder"])
    return True


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


def ffmpeg_candidates(
    worktree: Path,
    profile: str = "static",
    architecture: str = "",
    readelf: str = "",
) -> list[tuple[Path, str]]:
    names = ("ffmpeg_g", "ffmpeg")
    roots = [build_dir(worktree, profile), worktree]
    out: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        for name in names:
            candidate = root / name
            try:
                resolved = candidate.resolve()
            except OSError:
                resolved = candidate
            if resolved not in seen and expected_elf(candidate, architecture, readelf):
                seen.add(resolved)
                out.append((candidate, "ffmpeg"))
        for lib in root.glob("libav*/*.so*"):
            try:
                resolved = lib.resolve()
            except OSError:
                resolved = lib
            if resolved not in seen and expected_elf(lib, architecture, readelf):
                seen.add(resolved)
                out.append((lib, re.sub(r"\.so(?:\.\d+)*$", ".so", lib.name)))
    return out


def has_built_ffmpeg(
    worktree: Path,
    profile: str,
    config: BuildConfig | None = None,
    *,
    require_marker: bool = True,
) -> bool:
    if config is None:
        return bool(ffmpeg_candidates(worktree, profile))
    if require_marker and not has_build_marker(worktree, profile, config):
        return False
    return bool(
        ffmpeg_candidates(
            worktree,
            profile,
            architecture=config.architecture,
            readelf=config.toolchain.readelf,
        )
    )


def run_configure_and_make(config: BuildConfig, worktree: Path, profile: str, log_path: Path, log: StageLogger) -> bool:
    env = build_env(config)
    build = build_dir(worktree, profile)
    cwd = build_cwd(worktree, profile)
    for command in configure_commands(config, worktree, profile):
        clean_build_dir(build)
        clean_in_tree_config(worktree)
        configure = run_command(command, cwd=cwd, log_path=log_path, env=env)
        if not configure.ok:
            continue
        if not enable_profile_components(worktree, profile, log):
            continue
        make = run_command(["make", f"-j{os.cpu_count() or 4}", "ffmpeg_g"], cwd=cwd, log_path=log_path, env=env)
        if not make.ok:
            make = run_command(["make", f"-j{os.cpu_count() or 4}", "ffmpeg"], cwd=cwd, log_path=log_path, env=env)
        if not make.ok:
            make = run_command(["make", f"-j{os.cpu_count() or 4}"], cwd=cwd, log_path=log_path, env=env)
        if make.ok and has_built_ffmpeg(worktree, profile, config, require_marker=False):
            write_build_marker(config, worktree, profile)
            return True
    log.warn("ffmpeg build attempts exhausted", worktree=str(worktree), profile=profile)
    return False


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
    log_dir = current_log_root(config.output) / "build" / stage / config.project
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{commit[:12]}-{build_token(config, profile)}.log"
    if has_built_ffmpeg(worktree, profile, config):
        return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=[str(log_path)], notes="reused existing build")
    ok = run_configure_and_make(config, worktree, profile, log_path, log)
    if ok:
        remove_build_logs(config, [str(log_path)], log, success=True, reason=f"{stage} successful ffmpeg build")
    return BuildOutput(commit=commit, worktree=worktree, ok=ok, log_paths=[str(log_path)], notes="")


def choose_binary(worktree: Path, functions: list[str], preferred: str = "", profile: str = "static") -> BinaryMatch | None:
    metadata = build_metadata(worktree, profile)
    architecture = metadata.get("architecture", "")
    nm = metadata.get("nm", "")
    readelf = metadata.get("readelf", "")
    if architecture == "aarch64" and (not nm or not readelf):
        return None
    candidates = ffmpeg_candidates(worktree, profile, architecture=architecture, readelf=readelf)
    if not candidates:
        return None
    if not architecture and any(elf_architecture(path) == "aarch64" for path, _ in candidates):
        return None
    wanted = [fn for fn in functions if fn]
    ranked: list[tuple[int, Path, str, list[str]]] = []
    for path, binary_name in candidates:
        symbols = symbol_names(path, nm=nm or "nm")
        missing = [fn for fn in wanted if fn not in symbols and fn.lstrip("_") not in symbols]
        score = len(missing)
        if preferred and binary_name != preferred:
            score += 1000
        ranked.append((score, path, binary_name, missing))
    ranked.sort(key=lambda item: item[0])
    _, path, binary_name, missing = ranked[0]
    return BinaryMatch(path=path, binary_name=binary_name, missing=missing)


def find_binary_by_name(worktree: Path, binary_name: str, profile: str = "static") -> Path | None:
    metadata = build_metadata(worktree, profile)
    architecture = metadata.get("architecture", "")
    readelf = metadata.get("readelf", "")
    if architecture == "aarch64" and not readelf:
        return None
    normalized = (binary_name or "").lower()
    candidates = ffmpeg_candidates(worktree, profile, architecture=architecture, readelf=readelf)
    if not architecture and any(elf_architecture(path) == "aarch64" for path, _ in candidates):
        return None
    for path, name in candidates:
        if normalized in {"", "ffmpeg", "ffmpeg_g"} or normalized == name:
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
        compiler_id = path_token(compiler, "compiler")
        opt_id = path_token(opt, "opt")
        return f"{project}-{version}-{binary_name}-{compiler_id}-{opt_id}"
    return f"{project}-{version}-{binary_name}"
