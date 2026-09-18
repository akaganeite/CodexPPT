from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from builder.architecture import elf_architecture, matches_elf_architecture
from builder.config import BuildConfig, path_token
from builder.logging import StageLogger, current_log_root
from binarybuild.build_log_cleanup import remove_build_logs
from utils.command import run_command

ADAPTER_VERSION = "openssl-reference-20260909.1"
SUPPORTED_ARCHITECTURES = ("x86_64", "aarch64")
AARCH64_UNSAFE_ENV_VARS = (
    "ARFLAGS",
    "AS",
    "ASFLAGS",
    "COMPILER_PATH",
    "CPATH",
    "CPP",
    "CPPFLAGS",
    "CPLUS_INCLUDE_PATH",
    "C_INCLUDE_PATH",
    "GCC_EXEC_PREFIX",
    "KERNEL_BITS",
    "LD",
    "LDFLAGS",
    "LDLIBS",
    "LIBRARY_PATH",
    "LIBS",
    "OBJC_INCLUDE_PATH",
    "PKG_CONFIG",
    "PKG_CONFIG_LIBDIR",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_SYSROOT_DIR",
    "RC",
    "RCFLAGS",
    "WINDRES",
)


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
    return "-".join(
        (
            path_token(profile, "static"),
            path_token(config.build_variant, "variant"),
            path_token(ADAPTER_VERSION, "adapter"),
        )
    )


def ensure_worktree(config: BuildConfig, ref: str, log: StageLogger, profile: str = "static") -> Path | None:
    config.worktree_root.mkdir(parents=True, exist_ok=True)
    commit_proc = subprocess.run(
        ["git", "-C", str(config.repo), "rev-parse", f"{ref}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if commit_proc.returncode:
        log.error("cannot resolve ref", ref=ref, stderr=commit_proc.stderr.strip())
        return None
    commit = commit_proc.stdout.strip()
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
        log.warn("worktree path exists but is not reusable", ref=ref, path=str(worktree))
        return None
    add = subprocess.run(
        ["git", "-C", str(config.repo), "worktree", "add", "--detach", str(worktree), commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if add.returncode:
        log.error("failed to create worktree", ref=ref, path=str(worktree), stderr=add.stderr.strip())
        return None
    return worktree


def build_env(config: BuildConfig) -> dict[str, str]:
    env = os.environ.copy()
    toolchain = config.toolchain
    if config.architecture == "aarch64":
        for name in AARCH64_UNSAFE_ENV_VARS:
            env.pop(name, None)
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
            "CROSS_COMPILE": "",
        }
    )
    flags = [*toolchain.compiler_flags, "-g3", config.opt.strip()]
    common_flags = " ".join(flag for flag in flags if flag)
    env["CFLAGS"] = common_flags
    env["CXXFLAGS"] = common_flags
    toolchain_ldflags = " ".join(toolchain.compiler_flags)
    existing_ldflags = "" if config.architecture == "aarch64" else env.get("LDFLAGS", "").strip()
    env["LDFLAGS"] = " ".join(part for part in (existing_ldflags, toolchain_ldflags) if part)
    if config.architecture == "aarch64":
        env["PKG_CONFIG"] = "false"
    return env


def supports_symlinks(path: Path) -> bool:
    path.mkdir(parents=True, exist_ok=True)
    src = path / ".agentic_symlink_test_src"
    dst = path / ".agentic_symlink_test_dst"
    try:
        src.write_text("x", encoding="utf-8")
        os.symlink(src.name, dst)
        return dst.is_symlink()
    except OSError:
        return False
    finally:
        for item in (dst, src):
            try:
                item.unlink()
            except OSError:
                pass


def profile_kind(profile: str) -> str:
    return "shared" if profile.startswith("shared") else "static"


def profile_options(profile: str) -> list[str]:
    options: list[str] = []
    if "zlib" in profile:
        options.append("zlib")
    return options


def static_compat_options() -> list[str]:
    return ["no-engine", "no-hw", "no-gost"]


def effective_profile(config: BuildConfig, requested: str, log: StageLogger) -> str:
    if profile_kind(requested) == "shared" and not supports_symlinks(config.worktree_root):
        log.warn(
            "shared profile requested on filesystem without symlink support; attempting shared build",
            requested=requested,
            root=str(config.worktree_root),
        )
    return requested


def build_marker_path(worktree: Path, profile: str) -> Path:
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
    for marker in sorted(worktree.glob(".agentic-build-*.marker")):
        metadata = read_marker(marker)
        if metadata.get("adapter") == ADAPTER_VERSION:
            return metadata
    return {}


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


def profile_has_expected_output(
    worktree: Path,
    profile: str,
    architecture: str = "",
    readelf: str = "",
) -> bool:
    if profile_kind(profile) == "shared":
        built_libcrypto = any(expected_elf(path, architecture, readelf) for path in worktree.glob("libcrypto.so*"))
        built_libssl = any(expected_elf(path, architecture, readelf) for path in worktree.glob("libssl.so*"))
        if "libcrypto" in profile:
            return built_libcrypto
        if "libssl" in profile:
            return built_libssl
        built_main = built_libcrypto or built_libssl
    else:
        built_main = expected_elf(worktree / "apps" / "openssl", architecture, readelf)
    # OpenSSL 3 keeps legacy ciphers in a module, even with no-shared.
    legacy = "providers/legacy.so"
    return built_main and (
        legacy not in makefile_tokens(worktree / "Makefile", "MODULES")
        or expected_elf(worktree / legacy, architecture, readelf)
    )


def has_built_openssl(worktree: Path, profile: str, config: BuildConfig | None = None) -> bool:
    metadata = build_metadata(worktree, profile)
    if config is not None:
        if metadata != parse_marker(build_signature(config, profile)):
            return False
        architecture = config.architecture
        readelf = config.toolchain.readelf
    else:
        architecture = metadata.get("architecture", "")
        readelf = metadata.get("readelf", "")
        if architecture == "aarch64" and not readelf:
            return False
    return profile_has_expected_output(worktree, profile, architecture, readelf)


def write_build_marker(config: BuildConfig, worktree: Path, profile: str) -> None:
    build_marker_path(worktree, profile).write_text(build_signature(config, profile), encoding="utf-8")


def apply_worktree_compat_patches(worktree: Path, log: StageLogger, commit: str) -> None:
    patched_paths: list[Path] = []
    candidates = [worktree / "Configure", worktree / "ssl" / "ssl_ciph.c", *worktree.rglob("build.info")]
    for path in candidates:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warn("failed to read OpenSSL file for compatibility patching", commit=commit, path=str(path), error=str(exc))
            continue
        patched = text.replace(
            "use if $^O ne \"VMS\", 'File::Glob' => qw/glob/;",
            "use if $^O ne \"VMS\", 'File::Glob' => qw/:glob/;",
        )
        patched = patched.replace(
            "{0, SSL_TXT_kDH, 0, SSL_kDHr | SSL_kDHd, 0, 0, 0, 0, 0, 0, 0, 0}, /\n"
            "        {0, SSL_TXT_kEDH",
            "{0, SSL_TXT_kDH, 0, SSL_kDHr | SSL_kDHd, 0, 0, 0, 0, 0, 0, 0, 0},\n"
            "    {0, SSL_TXT_kEDH",
        )
        if patched == text:
            continue
        try:
            path.write_text(patched, encoding="utf-8")
            if path.name == "Configure":
                path.chmod(path.stat().st_mode | 0o755)
        except OSError as exc:
            log.warn("failed to write OpenSSL compatibility patch", commit=commit, path=str(path), error=str(exc))
            continue
        patched_paths.append(path)
    if patched_paths:
        log.trace(
            "patched OpenSSL files for build compatibility",
            commit=commit,
            paths=[str(path) for path in patched_paths],
        )


def enforce_configured_opt(worktree: Path, opt: str, log: StageLogger, commit: str) -> None:
    if not opt:
        return
    makefile = worktree / "Makefile"
    if not makefile.exists():
        return
    try:
        text = makefile.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warn("failed to read generated Makefile for opt normalization", commit=commit, error=str(exc))
        return
    normalized = re.sub(r"(?<!\S)-O(?:0|1|2|3|s|g|fast)(?!\S)", opt, text)
    if normalized == text:
        return
    try:
        makefile.write_text(normalized, encoding="utf-8")
    except OSError as exc:
        log.warn("failed to normalize generated Makefile opt", commit=commit, opt=opt, error=str(exc))


def makefile_tokens(makefile: Path, variable: str) -> list[str]:
    try:
        lines = makefile.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    values: list[str] = []
    collecting = False
    current = ""
    prefix = f"{variable}="
    for raw_line in lines:
        line = raw_line.strip()
        if not collecting and not line.startswith(prefix):
            continue
        if not collecting:
            current = line[len(prefix) :].strip()
        else:
            current += " " + line
        if current.endswith("\\"):
            current = current[:-1].strip()
            collecting = True
            continue
        values.extend(current.split())
        collecting = False
        current = ""
    return values


def materialize_header_links(worktree: Path, log: StageLogger, commit: str) -> None:
    include_dir = worktree / "include" / "openssl"
    include_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for makefile in sorted(worktree.rglob("Makefile")):
        directory = makefile.parent
        for header in makefile_tokens(makefile, "EXHEADER"):
            if "$" in header or "/" in header:
                continue
            src = directory / header
            dest = include_dir / header
            if not src.exists():
                continue
            try:
                if dest.is_symlink() or dest.exists():
                    dest.unlink()
                shutil.copy2(src, dest)
                dest.chmod(0o644)
            except OSError as exc:
                log.warn("failed to materialize OpenSSL header", commit=commit, header=header, src=str(src), dest=str(dest), error=str(exc))
                continue
            copied += 1
    if copied:
        log.trace("materialized OpenSSL headers", commit=commit, count=copied, include=str(include_dir))


def materialize_shared_library_aliases(worktree: Path, log: StageLogger, commit: str) -> None:
    makefile = worktree / "Makefile"
    if not makefile.exists():
        return
    try:
        text = makefile.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warn("failed to read generated Makefile for shared alias materialization", commit=commit, error=str(exc))
        return
    patched = re.sub(
        r"ln -s (lib(?:crypto|ssl)\.so\.\S+) (lib(?:crypto|ssl)\.so)",
        r"cp -f \1 \2",
        text,
    )
    if patched == text:
        return
    try:
        makefile.write_text(patched, encoding="utf-8")
    except OSError as exc:
        log.warn("failed to materialize shared library aliases", commit=commit, error=str(exc))
        return
    log.trace("rewrote OpenSSL shared library aliases as copies", commit=commit, makefile=str(makefile))


def should_run_make_depend(worktree: Path) -> bool:
    makefile = worktree / "Makefile"
    if not makefile.exists():
        return False
    try:
        text = makefile.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if "build_generated:" in text:
        return False
    test_makefile = worktree / "test" / "Makefile"
    if test_makefile.exists():
        try:
            test_text = test_makefile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            test_text = ""
        missing_test_sources = [
            token
            for token in re.findall(r"(?<![A-Za-z0-9_./-])([A-Za-z0-9_./-]+\.c)(?![A-Za-z0-9_./-])", test_text)
            if not (test_makefile.parent / token).exists()
        ]
        if missing_test_sources:
            return False
    return re.search(r"^depend\s*:", text, re.MULTILINE) is not None


def configure_defines_target(worktree: Path, target: str) -> bool:
    candidates = [worktree / "Configure", *(worktree / "Configurations").glob("*.conf")]
    quoted = (f'"{target}"', f"'{target}'")
    for path in candidates:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(token in text for token in quoted):
            return True
    return False


def configure_target(config: BuildConfig, worktree: Path | None = None) -> str:
    host_arch = config.toolchain.configure_host.split("-", 1)[0].lower().replace("arm64", "aarch64")
    if config.architecture == "aarch64" and host_arch != "aarch64":
        raise ValueError(f"AArch64 OpenSSL build requires an AArch64 configure host, got {config.toolchain.configure_host}")
    if config.architecture == "x86_64" and host_arch not in {"x86_64", "amd64"}:
        raise ValueError(f"x86_64 OpenSSL build requires an x86_64 configure host, got {config.toolchain.configure_host}")
    if config.architecture == "aarch64":
        if worktree is not None and not configure_defines_target(worktree, "linux-aarch64"):
            if configure_defines_target(worktree, "linux-generic64"):
                return "linux-generic64"
        return "linux-aarch64"
    return "linux-x86_64"


def configure_commands(config: BuildConfig, profile: str, worktree: Path | None = None) -> list[list[str]]:
    opt = config.opt.strip()
    options = profile_options(profile)
    compiler_flags = list(config.toolchain.compiler_flags)
    target = configure_target(config, worktree)
    if profile_kind(profile) == "shared":
        commands = [
            [
                "perl",
                "./Configure",
                target,
                "shared",
                *options,
                "no-tests",
                "no-docs",
                *compiler_flags,
                "-g3",
                opt,
            ],
            ["perl", "./Configure", target, "shared", *options, "no-tests", *compiler_flags, "-g3", opt],
        ]
        if config.architecture == "x86_64":
            commands.extend(
                [
                    ["./config", "-d", "shared", *options, "no-tests", "no-docs", opt],
                    ["./config", "-d", "shared", *options, "no-tests", opt],
                ]
            )
        return [[arg for arg in command if arg] for command in commands]
    compat = static_compat_options()
    strict_commands = [
        [
            "perl",
            "./Configure",
            target,
            "no-shared",
            *compat,
            *options,
            "no-tests",
            "no-docs",
            *compiler_flags,
            "-g3",
            opt,
        ],
        [
            "perl",
            "./Configure",
            target,
            "no-shared",
            *compat,
            *options,
            "no-tests",
            *compiler_flags,
            "-g3",
            opt,
        ],
        ["perl", "./Configure", target, "no-shared", *compat, *options, *compiler_flags, "-g3", opt],
    ]
    relaxed_commands = [
        [
            "perl",
            "./Configure",
            target,
            "no-shared",
            *options,
            "no-tests",
            "no-docs",
            *compiler_flags,
            "-g3",
            opt,
        ],
        ["perl", "./Configure", target, "no-shared", *options, "no-tests", *compiler_flags, "-g3", opt],
        ["perl", "./Configure", target, "no-shared", *options, *compiler_flags, "-g3", opt],
    ]
    if config.architecture == "aarch64":
        commands = [*strict_commands, *relaxed_commands]
    else:
        commands = [
            *strict_commands,
            ["./config", "-d", "no-shared", *compat, *options, "no-tests", "no-docs", opt],
            ["./config", "-d", "no-shared", *compat, *options, "no-tests", opt],
            ["./config", "-d", "no-shared", *compat, *options, opt],
            *relaxed_commands,
            ["./config", "-d", "no-shared", *options, "no-tests", "no-docs", opt],
            ["./config", "-d", "no-shared", *options, "no-tests", opt],
            ["./config", "-d", "no-shared", *options, opt],
        ]
    return [[arg for arg in command if arg] for command in commands]


def configured_ar_override(config: BuildConfig, worktree: Path | None = None) -> str:
    suffix = ""
    makefile = worktree / "Makefile" if worktree is not None else None
    if makefile is not None and makefile.exists():
        try:
            text = makefile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        match = re.search(r"^AR\s*=\s*(.*)$", text, re.MULTILINE)
        if match:
            configured = match.group(1).strip().split(None, 1)
            suffix = configured[1] if len(configured) == 2 else ""
    parts = [config.toolchain.ar, suffix]
    return "AR=" + " ".join(part for part in parts if part)


def make_tool_overrides(config: BuildConfig, worktree: Path | None = None) -> list[str]:
    toolchain = config.toolchain
    return [
        f"CC={toolchain.c_compiler}",
        f"CXX={toolchain.cxx_compiler}",
        configured_ar_override(config, worktree),
        f"RANLIB={toolchain.ranlib}",
        f"NM={toolchain.nm}",
        f"OBJDUMP={toolchain.objdump}",
        f"OBJCOPY={toolchain.objcopy}",
        f"STRIP={toolchain.strip}",
        f"READELF={toolchain.readelf}",
        "CROSS_COMPILE=",
    ]


def make_command(
    config: BuildConfig,
    target: str = "",
    parallel: bool = True,
    worktree: Path | None = None,
) -> list[str]:
    command = ["make"]
    if parallel:
        command.extend(["-j", str(max(1, os.cpu_count() or 1))])
    command.extend(make_tool_overrides(config, worktree))
    if target:
        command.append(target)
    return command


def make_commands(config: BuildConfig, profile: str, worktree: Path | None = None) -> list[list[str]]:
    makefile = worktree / "Makefile" if worktree is not None else None
    text = ""
    if makefile is not None and makefile.exists():
        try:
            text = makefile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if "build_generated:" not in text and "build_sw:" not in text:
            if "build_apps:" in text:
                return [make_command(config, "build_apps", worktree=worktree)]
            return [make_command(config, worktree=worktree)]
    if profile_kind(profile) == "shared":
        direct_targets: list[str] = []
        if "libcrypto" in profile:
            direct_targets.extend(re.findall(r"^(libcrypto\.so\.[^:\s]+)\s*:", text, re.MULTILINE))
        if "libssl" in profile:
            direct_targets.extend(re.findall(r"^(libssl\.so\.[^:\s]+)\s*:", text, re.MULTILINE))
        if direct_targets:
            commands = [make_command(config, "build_generated", worktree=worktree)]
            commands.extend(
                make_command(config, target, worktree=worktree)
                for target in sorted(dict.fromkeys(direct_targets))
            )
            commands.extend(
                [
                    make_command(config, "build_sw", worktree=worktree),
                    make_command(config, worktree=worktree),
                ]
            )
            return commands
        return [
            make_command(config, "build_generated", worktree=worktree),
            make_command(config, "build_sw", worktree=worktree),
            make_command(config, worktree=worktree),
        ]
    commands = [
        make_command(config, "build_generated", worktree=worktree),
        make_command(config, "apps/openssl", worktree=worktree),
    ]
    if makefile is not None and "providers/legacy.so" in makefile_tokens(makefile, "MODULES"):
        commands.append(make_command(config, "providers/legacy.so", worktree=worktree))
    return [
        *commands,
        make_command(config, "build_sw", worktree=worktree),
        make_command(config, worktree=worktree),
    ]


def compile_openssl_commit(config: BuildConfig, ref: str, stage: str, log: StageLogger, profile: str = "static") -> BuildOutput:
    if config.architecture not in SUPPORTED_ARCHITECTURES:
        return BuildOutput(
            commit=ref,
            worktree=Path(),
            ok=False,
            log_paths=[],
            notes=f"unsupported architecture: {config.architecture}",
        )
    profile = effective_profile(config, profile, log)
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
    apply_worktree_compat_patches(worktree, log, commit)
    build_log_dir = current_log_root(config.output) / "trace" / f"{stage}_builds"
    log_paths: list[str] = []
    successful_log_paths: list[str] = []
    if has_built_openssl(worktree, profile, config):
        log.trace("reuse built worktree", commit=commit, profile=profile, worktree=str(worktree))
        return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths, notes="reused existing build")

    env = build_env(config)
    for index, configure in enumerate(configure_commands(config, profile, worktree), start=1):
        if (worktree / "Makefile").exists():
            clean_log = build_log_dir / f"{commit[:12]}-{profile}-clean-{index}.log"
            result = run_command(
                make_command(config, "clean", parallel=False, worktree=worktree),
                cwd=worktree,
                log_path=clean_log,
                env=env,
            )
            log_paths.append(str(clean_log))
            if result.ok:
                successful_log_paths.append(str(clean_log))
        configure_log = build_log_dir / f"{commit[:12]}-{profile}-config-{index}.log"
        result = run_command(configure, cwd=worktree, log_path=configure_log, env=env)
        log_paths.append(str(configure_log))
        if not result.ok:
            log.warn("openssl configure failed", commit=commit, profile=profile, command=configure, log=str(configure_log))
            continue
        successful_log_paths.append(str(configure_log))
        enforce_configured_opt(worktree, config.opt.strip(), log, commit)
        if not supports_symlinks(worktree):
            materialize_header_links(worktree, log, commit)
            materialize_shared_library_aliases(worktree, log, commit)
        if should_run_make_depend(worktree):
            depend_log = build_log_dir / f"{commit[:12]}-{profile}-depend-{index}.log"
            result = run_command(
                make_command(config, "depend", parallel=False, worktree=worktree),
                cwd=worktree,
                log_path=depend_log,
                env=env,
            )
            log_paths.append(str(depend_log))
            if not result.ok:
                log.warn("openssl make depend failed", commit=commit, profile=profile, log=str(depend_log))
            else:
                successful_log_paths.append(str(depend_log))
        ok = False
        for make_index, make in enumerate(make_commands(config, profile, worktree), start=1):
            make_target = path_token(make[-1] if "=" not in make[-1] else "all", "all")
            make_log = build_log_dir / f"{commit[:12]}-{profile}-{index}-{make_index}-{make_target}.log"
            result = run_command(make, cwd=worktree, log_path=make_log, env=env)
            log_paths.append(str(make_log))
            if result.ok:
                successful_log_paths.append(str(make_log))
            if profile_has_expected_output(
                worktree,
                profile,
                architecture=config.architecture,
                readelf=config.toolchain.readelf,
            ):
                if not result.ok:
                    log.warn(
                        "openssl make returned nonzero after producing binary",
                        commit=commit,
                        profile=profile,
                        command=make,
                        log=str(make_log),
                    )
                ok = True
                break
            if not result.ok:
                log.warn("openssl make failed", commit=commit, profile=profile, command=make, log=str(make_log))
        if ok:
            write_build_marker(config, worktree, profile)
            log.trace("openssl commit built", commit=commit, profile=profile, worktree=str(worktree), logs=log_paths)
            remove_build_logs(config, successful_log_paths, log, success=True, reason=f"{stage} build completed")
            return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths)
    return BuildOutput(commit=commit, worktree=worktree, ok=False, log_paths=log_paths, notes="all configure/build commands failed")


def compile_commit(config: BuildConfig, ref: str, stage: str, log: StageLogger, profile: str = "static") -> BuildOutput:
    return compile_openssl_commit(config, ref, stage, log, profile=profile)


def candidates_for_binary(
    worktree: Path,
    profile: str = "static",
    architecture: str = "",
    readelf: str = "",
) -> list[tuple[Path, str]]:
    if not architecture and not readelf:
        metadata = build_metadata(worktree, profile)
        architecture = metadata.get("architecture", "")
        readelf = metadata.get("readelf", "")
    if architecture == "aarch64" and not readelf:
        return []
    if profile_kind(profile) == "shared":
        rules = [
            (worktree, "libssl", "so"),
            (worktree, "libcrypto", "so"),
            (worktree / "apps", "openssl", ""),
        ]
    else:
        rules = [
            (worktree / "apps", "openssl", ""),
            (worktree, "libssl", "so"),
            (worktree, "libcrypto", "so"),
        ]
    found: list[tuple[Path, str]] = []
    for directory, name, ext in rules:
        if not directory.exists():
            continue
        pattern = f"*{name}*{ext}*" if ext else f"{name}*"
        for path in sorted(directory.glob(pattern)):
            if path.is_file() and not path.is_symlink() and expected_elf(path, architecture, readelf):
                found.append((path, name))
    legacy = worktree / "providers" / "legacy.so"
    if not legacy.is_symlink() and expected_elf(legacy, architecture, readelf):
        found.append((legacy, "legacy"))
    return found


def choose_binary(worktree: Path, functions: list[str], preferred: str = "", profile: str = "static") -> BinaryMatch | None:
    metadata = build_metadata(worktree, profile)
    architecture = metadata.get("architecture", "")
    nm = metadata.get("nm", "")
    readelf = metadata.get("readelf", "")
    if architecture == "aarch64" and (not nm or not readelf):
        return None
    candidates = candidates_for_binary(
        worktree,
        profile=profile,
        architecture=architecture,
        readelf=readelf,
    )
    if not architecture and any(elf_architecture(path) == "aarch64" for path, _ in candidates):
        return None
    if preferred:
        candidates = [item for item in candidates if item[1] == preferred] + [item for item in candidates if item[1] != preferred]
    wanted = [function for function in functions if function]
    best: BinaryMatch | None = None
    for path, name in candidates:
        names = symbol_names(path, nm=nm or "nm")
        missing = [function for function in wanted if function not in names and function.lstrip("_") not in names]
        match = BinaryMatch(path=path, binary_name=name, missing=missing)
        if not missing:
            return match
        if best is None or len(missing) < len(best.missing):
            best = match
    return best


def find_binary_by_name(worktree: Path, binary_name: str, profile: str = "static") -> Path | None:
    metadata = build_metadata(worktree, profile)
    architecture = metadata.get("architecture", "")
    readelf = metadata.get("readelf", "")
    if architecture == "aarch64" and not readelf:
        return None
    candidates = candidates_for_binary(
        worktree,
        profile=profile,
        architecture=architecture,
        readelf=readelf,
    )
    if not architecture and any(elf_architecture(path) == "aarch64" for path, _ in candidates):
        return None
    for path, name in candidates:
        if name == binary_name:
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
