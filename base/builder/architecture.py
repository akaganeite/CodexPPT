from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from shutil import which


DEFAULT_ARCHITECTURE = "x86_64"
AARCH64_ARCHITECTURE = "aarch64"


def normalize_architecture(value: str) -> str:
    token = (value or DEFAULT_ARCHITECTURE).strip().lower().replace("-", "_")
    aliases = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }
    try:
        return aliases[token]
    except KeyError as exc:
        raise ValueError("--arch must be x86_64 or aarch64 (arm64 is accepted as an alias)") from exc


@dataclass(frozen=True)
class Toolchain:
    architecture: str
    triple: str
    compiler_family: str
    c_compiler: str
    cxx_compiler: str
    ar: str
    ranlib: str
    nm: str
    objdump: str
    objcopy: str
    strip: str
    readelf: str
    configure_host: str
    compiler_flags: tuple[str, ...] = ()

    def command_details(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "triple": self.triple,
            "compiler_family": self.compiler_family,
            "cc": self.c_compiler,
            "cxx": self.cxx_compiler,
            "ar": self.ar,
            "ranlib": self.ranlib,
            "nm": self.nm,
            "objdump": self.objdump,
            "objcopy": self.objcopy,
            "strip": self.strip,
            "readelf": self.readelf,
            "configure_host": self.configure_host,
            "compiler_flags": list(self.compiler_flags),
        }

    def required_commands(self) -> tuple[str, ...]:
        commands = (
            self.c_compiler,
            self.cxx_compiler,
            self.ar,
            self.ranlib,
            self.nm,
            self.objdump,
            self.objcopy,
            self.strip,
            self.readelf,
        )
        if self.architecture == AARCH64_ARCHITECTURE and self.compiler_family == "clang":
            commands += ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-g++")
        return commands


def resolve_toolchain(architecture: str, compiler: str) -> Toolchain:
    architecture = normalize_architecture(architecture)
    compiler = (compiler or "").strip()
    if architecture == DEFAULT_ARCHITECTURE:
        if compiler == "clang":
            return Toolchain(
                architecture=architecture,
                triple="x86_64-linux-gnu",
                compiler_family="clang",
                c_compiler="clang",
                cxx_compiler="clang++",
                ar="ar",
                ranlib="ranlib",
                nm="nm",
                objdump="objdump",
                objcopy="objcopy",
                strip="strip",
                readelf="readelf",
                configure_host="x86_64-linux-gnu",
            )
        return Toolchain(
            architecture=architecture,
            triple="x86_64-linux-gnu",
            compiler_family=compiler or "gcc",
            c_compiler=compiler or "gcc",
            cxx_compiler="g++" if "gcc" in (compiler or "gcc") else "clang++",
            ar="ar",
            ranlib="ranlib",
            nm="nm",
            objdump="objdump",
            objcopy="objcopy",
            strip="strip",
            readelf="readelf",
            configure_host="x86_64-linux-gnu",
        )

    if compiler not in {"gcc", "clang"}:
        raise ValueError("AArch64 builds require --compiler gcc or --compiler clang")
    if compiler == "gcc":
        c_compiler = "aarch64-linux-gnu-gcc"
        cxx_compiler = "aarch64-linux-gnu-g++"
        flags: tuple[str, ...] = ()
    else:
        c_compiler = "clang"
        cxx_compiler = "clang++"
        flags = ("--target=aarch64-linux-gnu", "--gcc-toolchain=/usr")
    return Toolchain(
        architecture=AARCH64_ARCHITECTURE,
        triple="aarch64-linux-gnu",
        compiler_family=compiler,
        c_compiler=c_compiler,
        cxx_compiler=cxx_compiler,
        ar="aarch64-linux-gnu-ar",
        ranlib="aarch64-linux-gnu-ranlib",
        nm="aarch64-linux-gnu-nm",
        objdump="aarch64-linux-gnu-objdump",
        objcopy="aarch64-linux-gnu-objcopy",
        strip="aarch64-linux-gnu-strip",
        readelf="aarch64-linux-gnu-readelf",
        configure_host="aarch64-linux-gnu",
        compiler_flags=flags,
    )


def validate_toolchain(architecture: str, compiler: str) -> Toolchain:
    toolchain = resolve_toolchain(architecture, compiler)
    if toolchain.architecture == DEFAULT_ARCHITECTURE:
        return toolchain
    missing = [command for command in toolchain.required_commands() if which(command) is None]
    if missing:
        detail = ", ".join(missing)
        raise ValueError(
            f"AArch64 GNU toolchain is incomplete; missing: {detail}. "
            "Install the cross C++ toolchain with: sudo apt install g++-aarch64-linux-gnu"
        )
    return toolchain


def elf_architecture(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return ""
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return ""
    byte_order = "little" if header[5] == 1 else "big" if header[5] == 2 else ""
    if not byte_order:
        return ""
    machine = int.from_bytes(header[18:20], byte_order)
    if machine == 0x3E:
        return "x86_64"
    if machine == 0xB7:
        return "aarch64"
    return ""


def matches_elf_architecture(path: Path, architecture: str) -> bool:
    return elf_architecture(path) == normalize_architecture(architecture)
