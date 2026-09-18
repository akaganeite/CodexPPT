from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from binarybuild.build_log_cleanup import remove_build_logs
from binarybuild.compile._curl_gnutls import prepare_gnutls_source, probe_gnutls
from builder.architecture import elf_architecture, matches_elf_architecture
from builder.config import BuildConfig, path_token
from builder.logging import StageLogger, current_log_root
from utils.command import run_command

ADAPTER_VERSION = "curl-reference-20260909.27"
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
    for command in ([nm, "--defined-only", "-A", str(path)], [nm, "--defined-only", "-D", "-A", str(path)]):
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


def effective_profile(config: BuildConfig, requested: str, log: StageLogger) -> str:
    if profile_kind(requested) == "shared" and not supports_symlinks(config.worktree_root):
        log.warn(
            "output filesystem does not support symlinks; curl shared build may stop after producing the real shared object",
            requested=requested,
            root=str(config.worktree_root),
        )
    return requested


def build_token(config: BuildConfig, profile: str) -> str:
    profile_token = path_token(profile, profile_kind(profile))
    token = f"{profile_token}-{path_token(config.build_variant, 'variant')}"
    return f"{token}-{path_token(ADAPTER_VERSION, 'adapter')}"


def build_marker_path(worktree: Path, profile: str) -> Path:
    return worktree / f".agentic-build-{path_token(profile, 'profile')}.marker"


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


def resolve_commit(repo: Path, ref: str, log: StageLogger) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{ref}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode:
        log.error("cannot resolve curl ref", ref=ref, stderr=proc.stderr.strip())
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
        log.warn("curl worktree path exists but is not reusable", ref=ref, path=str(worktree))
        return None
    add = subprocess.run(
        ["git", "-C", str(config.repo), "worktree", "add", "--detach", str(worktree), commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if add.returncode:
        log.error("failed to create curl worktree", ref=ref, path=str(worktree), stderr=add.stderr.strip())
        return None
    return worktree


def append_env_flags(env: dict[str, str], name: str, flags: list[str]) -> None:
    existing = env.get(name, "").strip()
    addition = " ".join(flag for flag in flags if flag)
    env[name] = " ".join(part for part in (existing, addition) if part)


def build_env(config: BuildConfig, profile: str = "") -> dict[str, str]:
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
    common = [
        *toolchain.compiler_flags,
        "-g3",
        config.opt.strip(),
        "-fno-omit-frame-pointer",
        "-fno-inline",
        "-Wno-error=deprecated-declarations",
        "-Wno-error=implicit-function-declaration",
        "-Wno-error=incompatible-pointer-types",
        "-Wno-error=int-conversion",
        "-Wno-error=discarded-qualifiers",
    ]
    flags = " ".join(flag for flag in common if flag)
    env["CFLAGS"] = flags
    env["CXXFLAGS"] = flags
    env["WARNINGS"] = "none"
    env.setdefault("AUTOMAKE", "automake")
    env.setdefault("AUTOCONF", "autoconf")
    env.setdefault("AUTOHEADER", "autoheader")
    env.setdefault("AUTORECONF", "autoreconf")
    env.setdefault("LIBTOOLIZE", "libtoolize")
    aclocal_dirs = [path for path in ("/usr/share/aclocal", "/usr/share/pkgconfig/aclocal") if Path(path).is_dir()]
    existing_aclocal_path = env.get("ACLOCAL_PATH", "").strip()
    env["ACLOCAL_PATH"] = os.pathsep.join([*aclocal_dirs, *([existing_aclocal_path] if existing_aclocal_path else [])])
    if config.architecture == "aarch64":
        env["PKG_CONFIG"] = "false"
    append_env_flags(env, "LDFLAGS", list(toolchain.compiler_flags))
    if wants_openldap(profile):
        ldap_root = ensure_local_openldap(config)
        if ldap_root is not None:
            append_env_flags(env, "CPPFLAGS", [f"-I{ldap_root / 'include'}"])
            append_env_flags(env, "LDFLAGS", [f"-L{ldap_root / 'lib'}"])
    return env


def profile_tokens(profile: str) -> set[str]:
    return {token for token in re.split(r"[^A-Za-z0-9]+", profile.lower()) if token}


def wants_gssapi(profile: str) -> bool:
    tokens = profile_tokens(profile)
    return "gss" in tokens or "gssapi" in tokens or "krb5" in tokens


def wants_old_idn(profile: str) -> bool:
    tokens = profile_tokens(profile)
    return "idn" in tokens or "libidn" in tokens


def wants_openldap(profile: str) -> bool:
    tokens = profile_tokens(profile)
    return "ldap" in tokens or "openldap" in tokens


def wants_gnutls(profile: str) -> bool:
    return "gnutls" in profile_tokens(profile)


def wants_schannel_wince(profile: str) -> bool:
    tokens = profile_tokens(profile)
    return "schannel" in tokens and "wince" in tokens


def wants_vtls_mbed_polar(profile: str) -> bool:
    tokens = profile_tokens(profile)
    return ("mbed" in tokens or "mbedtls" in tokens) and ("polar" in tokens or "polarssl" in tokens)


def wants_schannel_connect(profile: str) -> bool:
    tokens = profile_tokens(profile)
    return "schannel" in tokens and ("connect" in tokens or "winssl" in tokens)


def wants_source_symbol(profile: str) -> bool:
    tokens = profile_tokens(profile)
    return "source" in tokens and bool(tokens & {"cookie", "url", "smb"})


def source_symbol_kind(profile: str) -> str | None:
    tokens = profile_tokens(profile)
    for name in ("cookie", "url", "smb"):
        if name in tokens:
            return name
    return None


def needs_default_gssapi(worktree: Path | None) -> bool:
    if worktree is None:
        return False
    pattern = re.compile(r"\b(?:static\s+)?CURLcode\s+read_data\s*\(")
    for rel in ("lib/security.c", "lib/krb5.c"):
        path = worktree / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "HAVE_GSSAPI" in text and pattern.search(text):
            return True
    return False


def local_dep_root(config: BuildConfig, name: str) -> Path:
    return config.worktree_root / ".agentic-deps" / path_token(config.build_variant, "variant") / name


def build_static_stub(config: BuildConfig, root: Path, source: str, library: str) -> bool:
    src = root / f"{library}.c"
    obj = root / f"{library}.o"
    lib = root / "lib" / f"lib{library}.a"
    marker = root / f".{library}-{ADAPTER_VERSION}.marker"
    signature = build_signature(config, f"stub-{library}")
    try:
        if lib.exists() and marker.read_text(encoding="utf-8") == signature:
            return True
    except OSError:
        pass
    (root / "lib").mkdir(parents=True, exist_ok=True)
    src.write_text(source, encoding="utf-8")
    toolchain = config.toolchain
    compile_cmd = [
        toolchain.c_compiler,
        *toolchain.compiler_flags,
        "-fPIC",
        "-I",
        str(root / "include"),
        "-c",
        str(src),
        "-o",
        str(obj),
    ]
    if subprocess.run(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False).returncode:
        return False
    if subprocess.run([toolchain.ar, "rcs", str(lib), str(obj)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False).returncode:
        return False
    if subprocess.run([toolchain.ranlib, str(lib)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False).returncode:
        return False
    marker.write_text(signature, encoding="utf-8")
    return True


def ensure_local_openldap(config: BuildConfig) -> Path | None:
    root = local_dep_root(config, "openldap")
    include = root / "include"
    include.mkdir(parents=True, exist_ok=True)
    (include / "lber.h").write_text(
        r'''
#ifndef AGENTIC_CURL_LBER_H
#define AGENTIC_CURL_LBER_H
#include <stddef.h>
typedef long ber_slen_t;
typedef size_t ber_len_t;
typedef int ber_socket_t;
typedef struct BerElement BerElement;
typedef struct Sockbuf Sockbuf;
struct berval {
  ber_len_t bv_len;
  char *bv_val;
};
typedef struct Sockbuf_IO_Desc {
  void *sbiod_pvt;
} Sockbuf_IO_Desc;
typedef struct Sockbuf_IO {
  int (*sbi_setup)(Sockbuf_IO_Desc *, void *);
  int (*sbi_remove)(Sockbuf_IO_Desc *);
  int (*sbi_ctrl)(Sockbuf_IO_Desc *, int, void *);
  ber_slen_t (*sbi_read)(Sockbuf_IO_Desc *, void *, ber_len_t);
  ber_slen_t (*sbi_write)(Sockbuf_IO_Desc *, void *, ber_len_t);
  int (*sbi_close)(Sockbuf_IO_Desc *);
} Sockbuf_IO;
#define LBER_SB_OPT_DATA_READY 1
#define LBER_SBIOD_LEVEL_TRANSPORT 0
void ber_free(BerElement *ber, int freebuf);
void ber_memfree(void *ptr);
int ber_sockbuf_add_io(Sockbuf *sb, Sockbuf_IO *sbio, int layer, void *arg);
#endif
''',
        encoding="utf-8",
    )
    (include / "ldap.h").write_text(
        r'''
#ifndef AGENTIC_CURL_LDAP_H
#define AGENTIC_CURL_LDAP_H
#include <stddef.h>
#include <sys/time.h>
#include "lber.h"
typedef struct LDAP LDAP;
typedef struct LDAPMessage LDAPMessage;
typedef struct LDAPURLDesc {
  char *lud_scheme;
  char *lud_dn;
  int lud_scope;
  char *lud_filter;
  char **lud_attrs;
} LDAPURLDesc;
#define LDAP_URL_SUCCESS 0
#define LDAP_URL_ERR_MEM 1
#define LDAP_URL_ERR_PARAM 2
#define LDAP_URL_ERR_BADSCHEME 3
#define LDAP_URL_ERR_BADENCLOSURE 4
#define LDAP_URL_ERR_BADURL 5
#define LDAP_URL_ERR_BADHOST 6
#define LDAP_URL_ERR_BADATTRS 7
#define LDAP_URL_ERR_BADSCOPE 8
#define LDAP_URL_ERR_BADFILTER 9
#define LDAP_URL_ERR_BADEXTS 10
#define LDAP_SUCCESS 0
#define LDAP_PROTOCOL_ERROR 2
#define LDAP_SIZELIMIT_EXCEEDED 4
#define LDAP_VERSION2 2
#define LDAP_VERSION3 3
#define LDAP_OPT_DEBUG_LEVEL 0x5001
#define LDAP_OPT_PROTOCOL_VERSION 0x0011
#define LDAP_OPT_SOCKBUF 0x5002
#define LDAP_MSG_ONE 0
#define LDAP_MSG_RECEIVED 1
#define LDAP_RES_SEARCH_ENTRY 100
#define LDAP_RES_SEARCH_RESULT 101
#define LDAP_SASL_SIMPLE "simple"
LDAP *ldap_init(const char *host, int port);
int ldap_init_fd(ber_socket_t fd, int proto, const char *url, LDAP **ld);
int ldap_pvt_url_scheme2proto(const char *scheme);
int ldap_url_parse(const char *url, LDAPURLDesc **ludpp);
void ldap_free_urldesc(LDAPURLDesc *ludp);
int ldap_set_option(LDAP *ld, int option, const void *invalue);
int ldap_get_option(LDAP *ld, int option, void *outvalue);
int ldap_sasl_bind(LDAP *ld, const char *dn, const char *mechanism,
                   struct berval *cred, void *serverctrls,
                   void *clientctrls, int *msgidp);
int ldap_result(LDAP *ld, int msgid, int all, struct timeval *timeout,
                LDAPMessage **res);
int ldap_parse_result(LDAP *ld, LDAPMessage *res, int *errcodep,
                      char **matcheddnp, char **errmsgp, char ***referralsp,
                      void **serverctrlsp, int freeit);
const char *ldap_err2string(int err);
void ldap_memfree(void *p);
int ldap_unbind_ext(LDAP *ld, void *serverctrls, void *clientctrls);
int ldap_search_ext(LDAP *ld, const char *base, int scope,
                    const char *filter, char **attrs, int attrsonly,
                    void *serverctrls, void *clientctrls,
                    struct timeval *timeout, int sizelimit, int *msgidp);
int ldap_abandon_ext(LDAP *ld, int msgid, void *serverctrls,
                     void *clientctrls);
LDAPMessage *ldap_first_message(LDAP *ld, LDAPMessage *res);
LDAPMessage *ldap_next_message(LDAP *ld, LDAPMessage *msg);
int ldap_msgtype(LDAPMessage *msg);
int ldap_msgfree(LDAPMessage *lm);
int ldap_get_dn_ber(LDAP *ld, LDAPMessage *entry, BerElement **berout,
                    struct berval *dn);
int ldap_get_attribute_ber(LDAP *ld, LDAPMessage *entry, BerElement *ber,
                           struct berval *attr, struct berval **vals);
#endif
''',
        encoding="utf-8",
    )
    ldap_source = r'''
#include <stdlib.h>
#include <string.h>
#include "ldap.h"
struct LDAP { int unused; };
struct LDAPMessage { int unused; };
static LDAP global_ld;
LDAP *ldap_init(const char *host, int port) { (void)host; (void)port; return &global_ld; }
int ldap_init_fd(ber_socket_t fd, int proto, const char *url, LDAP **ld) { (void)fd; (void)proto; (void)url; if(ld) *ld = &global_ld; return LDAP_SUCCESS; }
int ldap_pvt_url_scheme2proto(const char *scheme) { (void)scheme; return 0; }
int ldap_url_parse(const char *url, LDAPURLDesc **ludpp) { if(!ludpp) return LDAP_URL_ERR_PARAM; *ludpp = calloc(1, sizeof(LDAPURLDesc)); if(!*ludpp) return LDAP_URL_ERR_MEM; (*ludpp)->lud_scheme = (char *)(url && !strncmp(url, "ldaps", 5) ? "ldaps" : "ldap"); return LDAP_URL_SUCCESS; }
void ldap_free_urldesc(LDAPURLDesc *ludp) { free(ludp); }
int ldap_set_option(LDAP *ld, int option, const void *invalue) { (void)ld; (void)option; (void)invalue; return LDAP_SUCCESS; }
int ldap_get_option(LDAP *ld, int option, void *outvalue) { (void)ld; if(option == LDAP_OPT_PROTOCOL_VERSION && outvalue) *(int *)outvalue = LDAP_VERSION3; else if(option == LDAP_OPT_SOCKBUF && outvalue) *(void **)outvalue = NULL; return LDAP_SUCCESS; }
int ldap_sasl_bind(LDAP *ld, const char *dn, const char *mechanism, struct berval *cred, void *serverctrls, void *clientctrls, int *msgidp) { (void)ld; (void)dn; (void)mechanism; (void)cred; (void)serverctrls; (void)clientctrls; if(msgidp) *msgidp = 1; return LDAP_SUCCESS; }
int ldap_result(LDAP *ld, int msgid, int all, struct timeval *timeout, LDAPMessage **res) { (void)ld; (void)msgid; (void)all; (void)timeout; if(res) *res = NULL; return 0; }
int ldap_parse_result(LDAP *ld, LDAPMessage *res, int *errcodep, char **matcheddnp, char **errmsgp, char ***referralsp, void **serverctrlsp, int freeit) { (void)ld; (void)res; (void)matcheddnp; (void)referralsp; (void)serverctrlsp; (void)freeit; if(errcodep) *errcodep = LDAP_SUCCESS; if(errmsgp) *errmsgp = NULL; return LDAP_SUCCESS; }
const char *ldap_err2string(int err) { (void)err; return "agentic openldap stub"; }
void ldap_memfree(void *p) { free(p); }
int ldap_unbind_ext(LDAP *ld, void *serverctrls, void *clientctrls) { (void)ld; (void)serverctrls; (void)clientctrls; return LDAP_SUCCESS; }
int ldap_search_ext(LDAP *ld, const char *base, int scope, const char *filter, char **attrs, int attrsonly, void *serverctrls, void *clientctrls, struct timeval *timeout, int sizelimit, int *msgidp) { (void)ld; (void)base; (void)scope; (void)filter; (void)attrs; (void)attrsonly; (void)serverctrls; (void)clientctrls; (void)timeout; (void)sizelimit; if(msgidp) *msgidp = 1; return LDAP_SUCCESS; }
int ldap_abandon_ext(LDAP *ld, int msgid, void *serverctrls, void *clientctrls) { (void)ld; (void)msgid; (void)serverctrls; (void)clientctrls; return LDAP_SUCCESS; }
LDAPMessage *ldap_first_message(LDAP *ld, LDAPMessage *res) { (void)ld; return res; }
LDAPMessage *ldap_next_message(LDAP *ld, LDAPMessage *msg) { (void)ld; (void)msg; return NULL; }
int ldap_msgtype(LDAPMessage *msg) { (void)msg; return LDAP_RES_SEARCH_RESULT; }
int ldap_msgfree(LDAPMessage *lm) { (void)lm; return LDAP_SUCCESS; }
int ldap_get_dn_ber(LDAP *ld, LDAPMessage *entry, BerElement **berout, struct berval *dn) { (void)ld; (void)entry; if(berout) *berout = NULL; if(dn) { dn->bv_len = 0; dn->bv_val = ""; } return LDAP_SUCCESS; }
int ldap_get_attribute_ber(LDAP *ld, LDAPMessage *entry, BerElement *ber, struct berval *attr, struct berval **vals) { (void)ld; (void)entry; (void)ber; if(attr) { attr->bv_len = 0; attr->bv_val = NULL; } if(vals) *vals = NULL; return LDAP_SUCCESS; }
'''
    lber_source = r'''
#include <stdlib.h>
#include "lber.h"
struct BerElement { int unused; };
struct Sockbuf { int unused; };
void ber_free(BerElement *ber, int freebuf) { (void)freebuf; free(ber); }
void ber_memfree(void *ptr) { free(ptr); }
int ber_sockbuf_add_io(Sockbuf *sb, Sockbuf_IO *sbio, int layer, void *arg) { (void)sb; (void)sbio; (void)layer; (void)arg; return 0; }
'''
    if not build_static_stub(config, root, ldap_source, "ldap"):
        return None
    if not build_static_stub(config, root, lber_source, "lber"):
        return None
    return root


def ensure_local_gssapi(config: BuildConfig) -> Path | None:
    root = local_dep_root(config, "gssapi")
    include = root / "include" / "gssapi"
    include.mkdir(parents=True, exist_ok=True)
    header = r'''
#ifndef AGENTIC_CURL_GSSAPI_H
#define AGENTIC_CURL_GSSAPI_H
#include <stddef.h>
#include <stdint.h>
#define GSS_ERROR(status) ((status) & 0x80000000U)
#define GSS_S_COMPLETE 0U
#define GSS_S_FAILURE 0x80000000U
#define GSS_S_CONTINUE_NEEDED 1U
#define GSS_C_QOP_DEFAULT 0
#define GSS_C_NO_OID ((gss_OID)0)
#define GSS_C_NO_NAME ((gss_name_t)0)
#define GSS_C_NO_BUFFER ((gss_buffer_t)0)
#define GSS_C_NO_CONTEXT ((gss_ctx_id_t)0)
#define GSS_C_NO_CREDENTIAL ((gss_cred_id_t)0)
#define GSS_C_NO_CHANNEL_BINDINGS ((gss_channel_bindings_t)0)
#define GSS_C_NULL_OID GSS_C_NO_OID
#define GSS_C_EMPTY_BUFFER {0, NULL}
#define GSS_C_AF_INET 2
#define GSS_C_GSS_CODE 1
#define GSS_C_MECH_CODE 2
#define GSS_C_DELEG_FLAG 1
#define GSS_C_MUTUAL_FLAG 2
#define GSS_C_REPLAY_FLAG 4
#define GSS_C_CONF_FLAG 16
#define GSS_C_INTEG_FLAG 32
#define GSS_C_DELEG_POLICY_FLAG 32768
#define GSS_C_INDEFINITE 0xffffffffU
typedef uint32_t OM_uint32;
typedef OM_uint32 gss_qop_t;
typedef struct gss_buffer_desc_struct {
  size_t length;
  void *value;
} gss_buffer_desc, *gss_buffer_t;
struct gss_cred_id_t_desc_struct;
typedef struct gss_cred_id_t_desc_struct *gss_cred_id_t;
typedef const struct gss_cred_id_t_desc_struct *gss_const_cred_id_t;
struct gss_ctx_id_t_desc_struct;
typedef struct gss_ctx_id_t_desc_struct *gss_ctx_id_t;
typedef const struct gss_ctx_id_t_desc_struct *gss_const_ctx_id_t;
struct gss_name_t_desc_struct;
typedef struct gss_name_t_desc_struct *gss_name_t;
typedef const struct gss_name_t_desc_struct *gss_const_name_t;
typedef struct gss_OID_desc_struct {
  OM_uint32 length;
  void *elements;
} gss_OID_desc, *gss_OID;
extern gss_OID GSS_C_NT_HOSTBASED_SERVICE;
typedef struct gss_channel_bindings_struct {
  OM_uint32 initiator_addrtype;
  gss_buffer_desc initiator_address;
  OM_uint32 acceptor_addrtype;
  gss_buffer_desc acceptor_address;
  gss_buffer_desc application_data;
} *gss_channel_bindings_t;
OM_uint32 gss_release_buffer(OM_uint32 *, gss_buffer_t);
OM_uint32 gss_init_sec_context(OM_uint32 *, gss_const_cred_id_t,
  gss_ctx_id_t *, gss_const_name_t, const gss_OID, OM_uint32, OM_uint32,
  const gss_channel_bindings_t, const gss_buffer_t, gss_OID *,
  gss_buffer_t, OM_uint32 *, OM_uint32 *);
OM_uint32 gss_delete_sec_context(OM_uint32 *, gss_ctx_id_t *, gss_buffer_t);
OM_uint32 gss_inquire_context(OM_uint32 *, gss_const_ctx_id_t, gss_name_t *,
  gss_name_t *, OM_uint32 *, gss_OID *, OM_uint32 *, int *, int *);
OM_uint32 gss_wrap(OM_uint32 *, gss_const_ctx_id_t, int, gss_qop_t,
  const gss_buffer_t, int *, gss_buffer_t);
OM_uint32 gss_unwrap(OM_uint32 *, gss_const_ctx_id_t, const gss_buffer_t,
  gss_buffer_t, int *, gss_qop_t *);
OM_uint32 gss_seal(OM_uint32 *, gss_ctx_id_t, int, int, gss_buffer_t, int *,
  gss_buffer_t);
OM_uint32 gss_unseal(OM_uint32 *, gss_ctx_id_t, gss_buffer_t, gss_buffer_t,
  int *, int *);
OM_uint32 gss_import_name(OM_uint32 *, const gss_buffer_t, const gss_OID,
  gss_name_t *);
OM_uint32 gss_release_name(OM_uint32 *, gss_name_t *);
OM_uint32 gss_display_name(OM_uint32 *, gss_const_name_t, gss_buffer_t,
  gss_OID *);
OM_uint32 gss_display_status(OM_uint32 *, OM_uint32, int, const gss_OID,
  OM_uint32 *, gss_buffer_t);
#endif
'''
    for rel in ("gssapi.h", "gssapi_generic.h", "gssapi_krb5.h"):
        (include / rel).write_text(header, encoding="utf-8")
    source = r'''
#include <stdlib.h>
#include <string.h>
#include "gssapi/gssapi.h"
gss_OID GSS_C_NT_HOSTBASED_SERVICE = (gss_OID)0;
static OM_uint32 ok(OM_uint32 *minor) { if(minor) *minor = 0; return GSS_S_COMPLETE; }
OM_uint32 gss_release_buffer(OM_uint32 *minor, gss_buffer_t buffer) { if(buffer && buffer->value) { free(buffer->value); buffer->value = NULL; buffer->length = 0; } return ok(minor); }
OM_uint32 gss_init_sec_context(OM_uint32 *minor, gss_const_cred_id_t cred, gss_ctx_id_t *ctx, gss_const_name_t name, const gss_OID mech, OM_uint32 req, OM_uint32 time_req, const gss_channel_bindings_t bindings, const gss_buffer_t input, gss_OID *actual, gss_buffer_t output, OM_uint32 *ret, OM_uint32 *time_rec) { (void)cred; (void)ctx; (void)name; (void)mech; (void)req; (void)time_req; (void)bindings; (void)input; (void)actual; if(output) { output->value = NULL; output->length = 0; } if(ret) *ret = 0; if(time_rec) *time_rec = 0; return ok(minor); }
OM_uint32 gss_delete_sec_context(OM_uint32 *minor, gss_ctx_id_t *ctx, gss_buffer_t output) { (void)output; if(ctx) *ctx = NULL; return ok(minor); }
OM_uint32 gss_inquire_context(OM_uint32 *minor, gss_const_ctx_id_t ctx, gss_name_t *src, gss_name_t *dst, OM_uint32 *life, gss_OID *mech, OM_uint32 *flags, int *local, int *open) { (void)ctx; if(src) *src = NULL; if(dst) *dst = NULL; if(life) *life = 0; if(mech) *mech = NULL; if(flags) *flags = 0; if(local) *local = 0; if(open) *open = 0; return ok(minor); }
OM_uint32 gss_wrap(OM_uint32 *minor, gss_const_ctx_id_t ctx, int conf, gss_qop_t qop, const gss_buffer_t input, int *state, gss_buffer_t output) { (void)ctx; (void)conf; (void)qop; if(state) *state = 0; if(output) { output->length = input ? input->length : 0; output->value = output->length ? malloc(output->length) : NULL; if(output->value && input && input->value) memcpy(output->value, input->value, output->length); } return ok(minor); }
OM_uint32 gss_unwrap(OM_uint32 *minor, gss_const_ctx_id_t ctx, const gss_buffer_t input, gss_buffer_t output, int *state, gss_qop_t *qop) { (void)qop; return gss_wrap(minor, ctx, 0, 0, input, state, output); }
OM_uint32 gss_seal(OM_uint32 *minor, gss_ctx_id_t ctx, int conf, int qop, gss_buffer_t input, int *state, gss_buffer_t output) { return gss_wrap(minor, ctx, conf, (gss_qop_t)qop, input, state, output); }
OM_uint32 gss_unseal(OM_uint32 *minor, gss_ctx_id_t ctx, gss_buffer_t input, gss_buffer_t output, int *state, int *qop) { (void)qop; return gss_wrap(minor, ctx, 0, 0, input, state, output); }
OM_uint32 gss_import_name(OM_uint32 *minor, const gss_buffer_t input, const gss_OID type, gss_name_t *name) { (void)input; (void)type; if(name) *name = NULL; return ok(minor); }
OM_uint32 gss_release_name(OM_uint32 *minor, gss_name_t *name) { if(name) *name = NULL; return ok(minor); }
OM_uint32 gss_display_name(OM_uint32 *minor, gss_const_name_t name, gss_buffer_t out, gss_OID *type) { (void)name; if(type) *type = NULL; if(out) { out->value = NULL; out->length = 0; } return ok(minor); }
OM_uint32 gss_display_status(OM_uint32 *minor, OM_uint32 value, int status_type, const gss_OID mech, OM_uint32 *ctx, gss_buffer_t str) { (void)value; (void)status_type; (void)mech; if(ctx) *ctx = 0; if(str) { str->value = NULL; str->length = 0; } return ok(minor); }
'''
    if not build_static_stub(config, root, source, "gssapi"):
        return None
    return root


def ensure_local_old_idn(config: BuildConfig) -> Path | None:
    root = local_dep_root(config, "libidn")
    include = root / "include"
    include.mkdir(parents=True, exist_ok=True)
    (include / "idn-free.h").write_text("void idn_free(void *ptr);\n", encoding="utf-8")
    (include / "idna.h").write_text(
        r'''
#ifndef AGENTIC_CURL_IDNA_H
#define AGENTIC_CURL_IDNA_H
typedef enum {
  IDNA_SUCCESS = 0,
  IDNA_STRINGPREP_ERROR = 1,
  IDNA_PUNYCODE_ERROR = 2,
  IDNA_CONTAINS_NON_LDH = 3,
  IDNA_CONTAINS_MINUS = 4,
  IDNA_INVALID_LENGTH = 5,
  IDNA_NO_ACE_PREFIX = 6,
  IDNA_ROUNDTRIP_VERIFY_ERROR = 7,
  IDNA_CONTAINS_ACE_PREFIX = 8,
  IDNA_ICONV_ERROR = 9,
  IDNA_MALLOC_ERROR = 10,
  IDNA_DLOPEN_ERROR = 11
} Idna_rc;
int idna_to_ascii_4i(const unsigned int *in, int inlen, char *out, int flags);
int idna_to_ascii_lz(const char *input, char **output, int flags);
int idna_to_unicode_lzlz(const char *input, char **output, int flags);
const char *idna_strerror(Idna_rc rc);
#endif
''',
        encoding="utf-8",
    )
    (include / "tld.h").write_text(
        r'''
#ifndef AGENTIC_CURL_TLD_H
#define AGENTIC_CURL_TLD_H
#include <stddef.h>
typedef enum { TLD_SUCCESS = 0 } Tld_rc;
int tld_check_lz(const char *in, size_t *errpos, const void *overrides);
const char *tld_strerror(Tld_rc rc);
#endif
''',
        encoding="utf-8",
    )
    (include / "stringprep.h").write_text(
        r'''
#ifndef AGENTIC_CURL_STRINGPREP_H
#define AGENTIC_CURL_STRINGPREP_H
const char *stringprep_check_version(const char *req_version);
const char *stringprep_locale_charset(void);
#endif
''',
        encoding="utf-8",
    )
    source = r'''
#include <stdlib.h>
#include <string.h>
#include "idna.h"
#include "tld.h"
#include "stringprep.h"
static char *dup_text(const char *input) {
  size_t len = input ? strlen(input) : 0;
  char *out = malloc(len + 1);
  if(out) {
    if(len) memcpy(out, input, len);
    out[len] = '\0';
  }
  return out;
}
void idn_free(void *ptr) { free(ptr); }
int idna_to_ascii_4i(const unsigned int *in, int inlen, char *out, int flags) { (void)in; (void)inlen; (void)flags; if(out) *out = '\0'; return IDNA_SUCCESS; }
int idna_to_ascii_lz(const char *input, char **output, int flags) { (void)flags; if(!output) return IDNA_MALLOC_ERROR; *output = dup_text(input); return *output ? IDNA_SUCCESS : IDNA_MALLOC_ERROR; }
int idna_to_unicode_lzlz(const char *input, char **output, int flags) { return idna_to_ascii_lz(input, output, flags); }
const char *idna_strerror(Idna_rc rc) { (void)rc; return "agentic libidn stub"; }
int tld_check_lz(const char *in, size_t *errpos, const void *overrides) { (void)in; (void)overrides; if(errpos) *errpos = 0; return TLD_SUCCESS; }
const char *tld_strerror(Tld_rc rc) { (void)rc; return "agentic tld stub"; }
const char *stringprep_check_version(const char *req_version) { (void)req_version; return "1.0-agentic"; }
const char *stringprep_locale_charset(void) { return "UTF-8"; }
'''
    if not build_static_stub(config, root, source, "idn"):
        return None
    return root


def patch_text_file(path: Path, replacements: list[tuple[str, str]]) -> bool:
    if not path.exists():
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    patched = text
    for old, new in replacements:
        patched = patched.replace(old, new)
    if patched == text:
        return False
    path.write_text(patched, encoding="utf-8")
    return True


def apply_worktree_compat_patches(worktree: Path, log: StageLogger, commit: str) -> None:
    patched: list[str] = []
    regenerate_configure = False
    replacements = [
        ("AM_CONFIG_HEADER(", "AC_CONFIG_HEADERS("),
        ("AC_CONFIG_HEADER(", "AC_CONFIG_HEADERS("),
        ("AM_PROG_CC_STDC", "AC_PROG_CC"),
    ]
    for rel in ("configure.ac", "acinclude.m4"):
        path = worktree / rel
        try:
            if patch_text_file(path, replacements):
                patched.append(str(path))
        except OSError as exc:
            log.warn("failed to patch curl autotools compatibility", commit=commit, path=str(path), error=str(exc))
    for rel in ("m4/curl-functions.m4", "acinclude.m4"):
        path = worktree / rel
        try:
            if patch_text_file(
                path,
                [
                    ("   AC_REQUIRE([AC_RUN_IFELSE])dnl\n\n", ""),
                    ("  AC_REQUIRE([AC_RUN_IFELSE])dnl\n\n", ""),
                ],
            ):
                patched.append(str(path))
                regenerate_configure = True
        except OSError as exc:
            log.warn("failed to patch curl cross-compile macro", commit=commit, path=str(path), error=str(exc))
    configure_ac = worktree / "configure.ac"
    if patch_text_file(configure_ac, [(
        "AC_CHECK_LIB(nettle, nettle_MD5Init, [ USE_GNUTLS_NETTLE=1 ])",
        "AC_CHECK_LIB(nettle, nettle_MD5Init, [ USE_GNUTLS_NETTLE=1 ],\n"
        "      [ AC_CHECK_LIB(nettle, nettle_md5_init, [ USE_GNUTLS_NETTLE=1 ]) ])",
    )]):
        # Old curl probes a removed Nettle entry point; test the real modern API.
        patched.append(str(configure_ac))
        regenerate_configure = True
    if regenerate_configure:
        configure = worktree / "configure"
        try:
            configure.unlink(missing_ok=True)
        except OSError as exc:
            log.warn("failed to invalidate curl configure script", commit=commit, path=str(configure), error=str(exc))
    for path in (worktree / "buildconf", worktree / "configure"):
        if path.exists():
            try:
                path.chmod(path.stat().st_mode | 0o755)
            except OSError:
                pass
    url_path = worktree / "lib" / "url.c"
    if patch_text_file(
        url_path,
        [
            (
                "#ifdef USE_NTLM\n"
                "  bool wantNTLMhttp = ((data->state.authhost.want & CURLAUTH_NTLM) ||\n"
                "                       (data->state.authhost.want & CURLAUTH_NTLM_WB)) &&\n"
                "    (needle->handler->protocol & PROTO_FAMILY_HTTP) ? TRUE : FALSE;\n"
                "#endif\n",
                "  bool wantNTLMhttp = ((data->state.authhost.want & CURLAUTH_NTLM) ||\n"
                "                       (data->state.authhost.want & CURLAUTH_NTLM_WB)) &&\n"
                "    (needle->handler->protocol & PROTO_FAMILY_HTTP) ? TRUE : FALSE;\n",
            ),
            (
                "      if((!(needle->handler->flags & PROTOPT_CREDSPERREQUEST)) ||\n"
                "         (wantNTLMhttp || check->ntlm.state != NTLMSTATE_NONE)) {\n",
                "      if((!(needle->handler->flags & PROTOPT_CREDSPERREQUEST))\n"
                "#ifdef USE_NTLM\n"
                "         || (wantNTLMhttp || check->ntlm.state != NTLMSTATE_NONE)\n"
                "#endif\n"
                "        ) {\n",
            ),
        ],
    ):
        patched.append(str(url_path))
    if patched:
        log.trace("patched curl files for build compatibility", commit=commit, paths=patched)


def run_bootstrap(config: BuildConfig, worktree: Path, build_log_dir: Path, commit: str, profile: str, log: StageLogger) -> tuple[bool, list[str]]:
    if (worktree / "configure").exists():
        return True, []
    env = build_env(config, profile)
    commands: list[list[str]] = [["libtoolize", "--force", "--copy"]]
    if (worktree / "buildconf").exists():
        commands.append(["./buildconf"])
    commands.extend(
        [
            ["autoreconf", "-fi"],
            ["autoreconf", "-fiv"],
        ]
    )
    log_paths: list[str] = []
    for index, command in enumerate(commands, start=1):
        log_path = build_log_dir / f"{commit[:12]}-{path_token(profile, 'profile')}-bootstrap-{index}.log"
        result = run_command(command, cwd=worktree, log_path=log_path, env=env)
        log_paths.append(str(log_path))
        if result.ok and (worktree / "configure").exists():
            log.trace("curl bootstrap completed", commit=commit, command=command, log=str(log_path))
            return True, log_paths
        log.warn("curl bootstrap failed", commit=commit, command=command, log=str(log_path))
    return (worktree / "configure").exists(), log_paths


def base_configure_options(include_idn_disable: bool = True) -> list[str]:
    options = [
        "--disable-dependency-tracking",
        "--disable-silent-rules",
        "--disable-werror",
        "--disable-curldebug",
        "--disable-manual",
        "--without-libpsl",
        "--without-nghttp2",
        "--without-ngtcp2",
        "--without-nghttp3",
        "--without-quiche",
        "--without-zsh-functions-dir",
        "--without-fish-functions-dir",
        "--without-brotli",
        "--without-zstd",
        "--without-libgsasl",
        "--without-librtmp",
        "--without-libssh2",
        "--without-libssh",
        "--without-wolfssl",
        "--without-gnutls",
        "--without-mbedtls",
        "--without-polarssl",
        "--without-nss",
        "--without-axtls",
        "--without-cyassl",
        "--without-secure-transport",
        "--without-schannel",
        "--without-amissl",
        "--without-bearssl",
        "--without-rustls",
        "--without-hyper",
        "--without-ca-bundle",
        "--without-ca-path",
    ]
    if include_idn_disable:
        options.insert(5, "--without-libidn")
    return options


def ldap_options_for_profile(profile: str) -> list[str]:
    if not wants_openldap(profile):
        return []
    return [
        "--enable-ldap",
        "--disable-ldaps",
        "--with-ldap-lib=ldap",
        "--with-lber-lib=lber",
    ]


def ssl_options_for_attempt(attempt: str) -> list[str]:
    if attempt == "openssl-new":
        return ["--with-openssl"]
    if attempt == "openssl-old":
        return ["--with-ssl"]
    if attempt == "no-ssl":
        return ["--without-ssl", "--without-openssl"]
    return []


def idn_options_for_attempt(attempt: str, old_idn_root: Path | None = None) -> list[str]:
    if attempt == "idn2":
        return ["--with-libidn2"]
    if attempt == "idn":
        if old_idn_root is not None:
            return [f"--with-libidn={old_idn_root}"]
        return ["--with-libidn"]
    if attempt == "no-idn":
        return ["--without-libidn2", "--without-libidn"]
    return []


def configure_commands(config: BuildConfig, profile: str, worktree: Path | None = None) -> list[list[str]]:
    shared = profile_kind(profile) == "shared"
    linkage = ["--enable-shared", "--disable-static"] if shared else ["--disable-shared", "--enable-static"]
    host = [f"--host={config.toolchain.configure_host}"] if config.architecture == "aarch64" else []
    if wants_gnutls(profile):
        # Never accept an OpenSSL/no-TLS fallback as a GnuTLS build.
        if config.architecture != "x86_64":
            return []
        common = [option for option in base_configure_options() if option != "--without-gnutls"]
        return [
            ["./configure", *linkage, *common, "--disable-ldap", "--disable-ldaps",
             *idn_options_for_attempt("no-idn"), "--without-openssl",
             "--with-gnutls", *extra]
            for extra in ([], ["--without-zlib"])
        ]
    old_idn_root = ensure_local_old_idn(config) if wants_old_idn(profile) else None
    use_gssapi = wants_gssapi(profile) or needs_default_gssapi(worktree)
    gssapi_root = ensure_local_gssapi(config) if use_gssapi else None
    openldap_root = ensure_local_openldap(config) if wants_openldap(profile) else None
    common = base_configure_options(include_idn_disable=old_idn_root is None)
    ldap_options = ldap_options_for_profile(profile) if openldap_root is not None else []
    gssapi_option_sets: list[list[str]] = []
    if gssapi_root is not None:
        gssapi_option_sets.append([f"--with-gssapi={gssapi_root}"])
    if not wants_gssapi(profile) or not gssapi_option_sets:
        gssapi_option_sets.append([])
    if old_idn_root is not None:
        idn_attempts = ("idn",)
    else:
        idn_attempts = ("idn2", "idn", "no-idn")
    commands = []
    for gssapi_options in gssapi_option_sets:
        for idn_attempt in idn_attempts:
            for ssl_attempt in ("openssl-old", "openssl-new", "no-ssl"):
                commands.append(
                    [
                        "./configure",
                        *host,
                        *linkage,
                        *common,
                        *ldap_options,
                        *gssapi_options,
                        *idn_options_for_attempt(idn_attempt, old_idn_root=old_idn_root),
                        *ssl_options_for_attempt(ssl_attempt),
                    ]
                )
        if old_idn_root is None:
            commands.append(
                [
                    "./configure",
                    *host,
                    *linkage,
                    *common,
                    "--without-zlib",
                    *ldap_options,
                    *gssapi_options,
                    *idn_options_for_attempt("no-idn"),
                    *ssl_options_for_attempt("no-ssl"),
                ]
            )
        if shared and old_idn_root is None:
            for idn_attempt, ssl_attempt, disable_zlib in (
                ("idn2", "openssl-old", False),
                ("no-idn", "no-ssl", False),
                ("no-idn", "no-ssl", True),
            ):
                commands.append(
                    [
                        "./configure",
                        *host,
                        "--disable-shared",
                        "--enable-static",
                        *common,
                        *(["--without-zlib"] if disable_zlib else []),
                        *ldap_options,
                        *gssapi_options,
                        *idn_options_for_attempt(idn_attempt),
                        *ssl_options_for_attempt(ssl_attempt),
                    ]
                )
    return commands


def make_commands(worktree: Path, env: dict[str, str] | None = None) -> list[list[str]]:
    jobs = str(max(1, os.cpu_count() or 1))
    overrides: list[str] = []
    if env is not None:
        try:
            makefile = (worktree / "Makefile").read_text(encoding="utf-8", errors="replace").replace("\\\n", " ")
        except OSError:
            makefile = ""
        for name in ("CFLAGS", "CXXFLAGS"):
            configured = re.search(rf"^{name}[ \t]*=[ \t]*(.*)$", makefile, re.MULTILINE)
            flags = configured.group(1).strip() if configured else ""
            # Older configure removes -g3. Reapply the contract at make time,
            # retaining configure's extra flags without enabling DEBUGBUILD.
            overrides.append(f"{name}={flags} {env.get(name, '')}".strip())
    commands: list[list[str]] = []
    if (worktree / "lib" / "Makefile").exists():
        commands.append(["make", "-j", jobs, *overrides, "-C", "lib", "all"])
    if (worktree / "src" / "Makefile").exists():
        commands.append(["make", "-j", jobs, *overrides, "-C", "src", "all"])
    commands.append(["make", "-j", jobs, *overrides])
    return commands


def make_clean(worktree: Path, build_log_dir: Path, commit: str, profile: str, index: int, env: dict[str, str]) -> str | None:
    if not (worktree / "Makefile").exists():
        return None
    log_path = build_log_dir / f"{commit[:12]}-{path_token(profile, 'profile')}-clean-{index}.log"
    run_command(["make", "distclean"], cwd=worktree, log_path=log_path, env=env)
    return str(log_path)


def cmake_bool(value: bool) -> str:
    return "ON" if value else "OFF"


def cmake_build_dir(worktree: Path, profile: str) -> Path:
    return worktree / f".agentic-cmake-{path_token(profile, 'profile')}"


def cmake_configure_commands(config: BuildConfig, worktree: Path, build_dir: Path, profile: str) -> list[list[str]]:
    shared = profile_kind(profile) == "shared"
    toolchain = config.toolchain
    env = build_env(config, profile)
    cross = []
    if config.architecture == "aarch64":
        cross = [
            "-DCMAKE_SYSTEM_NAME=Linux",
            "-DCMAKE_SYSTEM_PROCESSOR=aarch64",
            # Historical curl CMake files use try_run for these Linux probes.
            "-DHAVE_GLIBC_STRERROR_R:STRING=0",
            "-DHAVE_GLIBC_STRERROR_R__TRYRUN_OUTPUT:STRING=",
            "-DHAVE_POSIX_STRERROR_R:STRING=1",
            "-DHAVE_POSIX_STRERROR_R__TRYRUN_OUTPUT:STRING=",
            "-DHAVE_POLL_FINE:STRING=0",
            "-DHAVE_POLL_FINE__TRYRUN_OUTPUT:STRING=",
        ]
    common = [
        "cmake",
        "-S",
        str(worktree),
        "-B",
        str(build_dir),
        "-G",
        "Ninja",
        *cross,
        f"-DCMAKE_C_COMPILER={toolchain.c_compiler}",
        f"-DCMAKE_CXX_COMPILER={toolchain.cxx_compiler}",
        f"-DCMAKE_AR={toolchain.ar}",
        f"-DCMAKE_RANLIB={toolchain.ranlib}",
        f"-DCMAKE_NM={toolchain.nm}",
        f"-DCMAKE_OBJDUMP={toolchain.objdump}",
        f"-DCMAKE_OBJCOPY={toolchain.objcopy}",
        f"-DCMAKE_STRIP={toolchain.strip}",
        f"-DCMAKE_READELF={toolchain.readelf}",
        "-DCMAKE_BUILD_TYPE=Debug",
        f"-DCMAKE_C_FLAGS={env.get('CFLAGS', '')}",
        f"-DCMAKE_CXX_FLAGS={env.get('CXXFLAGS', '')}",
        f"-DBUILD_CURL_TESTS={cmake_bool(False)}",
        f"-DCURL_STATICLIB={cmake_bool(not shared)}",
        f"-DCURL_ZLIB={cmake_bool(False)}",
        f"-DCMAKE_USE_OPENSSL={cmake_bool(False)}",
        f"-DCURL_DISABLE_LDAP={cmake_bool(True)}",
        f"-DCURL_DISABLE_LDAPS={cmake_bool(True)}",
        f"-DCURL_DISABLE_DICT={cmake_bool(True)}",
        f"-DCURL_DISABLE_TELNET={cmake_bool(True)}",
    ]
    if shared:
        return [[*common, f"-DBUILD_CURL_EXE={cmake_bool(False)}"]]
    return [[*common, f"-DBUILD_CURL_EXE={cmake_bool(True)}"]]


def compile_cmake_fallback(
    config: BuildConfig,
    worktree: Path,
    build_log_dir: Path,
    commit: str,
    profile: str,
    log: StageLogger,
) -> tuple[bool, list[str]]:
    if wants_gnutls(profile):
        return False, []
    if not (worktree / "CMakeLists.txt").exists():
        return False, []
    log_paths: list[str] = []
    env = build_env(config, profile)
    build_dir = cmake_build_dir(worktree, profile)
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    for index, configure in enumerate(cmake_configure_commands(config, worktree, build_dir, profile), start=1):
        configure_log = build_log_dir / f"{commit[:12]}-{path_token(profile, 'profile')}-cmake-config-{index}.log"
        result = run_command(configure, cwd=worktree, log_path=configure_log, env=env)
        log_paths.append(str(configure_log))
        if not result.ok:
            log.warn("curl cmake configure failed", commit=commit, profile=profile, command=configure, log=str(configure_log))
            continue
        build_log = build_log_dir / f"{commit[:12]}-{path_token(profile, 'profile')}-cmake-build-{index}.log"
        result = run_command(
            ["cmake", "--build", str(build_dir), "-j", str(max(1, os.cpu_count() or 1))],
            cwd=worktree,
            log_path=build_log,
            env=env,
        )
        log_paths.append(str(build_log))
        if has_built_curl(worktree, profile, config, require_marker=False):
            if not result.ok:
                log.warn(
                    "curl cmake build returned nonzero after producing an ELF candidate",
                    commit=commit,
                    profile=profile,
                    log=str(build_log),
                )
            log.trace("curl cmake fallback built", commit=commit, profile=profile, build_dir=str(build_dir), logs=log_paths)
            return True, log_paths
        if not result.ok:
            log.warn("curl cmake build failed", commit=commit, profile=profile, log=str(build_log))
    return False, log_paths


def extract_function_source(text: str, name: str) -> str | None:
    pattern = re.compile(r"static\s+CURLcode\s+" + re.escape(name) + r"\s*\(", re.MULTILINE)
    for match in pattern.finditer(text):
        start = match.start()
        end_of_decl = text.find("\n", match.end())
        open_brace = text.find("{", match.end())
        semicolon = text.find(";", match.end(), open_brace if open_brace >= 0 else len(text))
        if open_brace >= 0 and semicolon < 0:
            break
    else:
        return None
    depth = 0
    for index in range(open_brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return None


def export_curlcode_function(body: str) -> str:
    return re.sub(r"\bstatic\s+CURLcode\s+", "CURLcode\n", body, count=1)


def compile_symbol_shared(
    config: BuildConfig,
    worktree: Path,
    build_log_dir: Path,
    commit: str,
    profile: str,
    source: str,
    log: StageLogger,
) -> tuple[bool, list[str]]:
    outdir = worktree / ".agentic-symbols"
    outdir.mkdir(parents=True, exist_ok=True)
    safe_profile = path_token(profile, "symbol")
    src = outdir / f"{safe_profile}.c"
    so = outdir / f"libcurl-{safe_profile}.so"
    src.write_text(source, encoding="utf-8")
    log_path = build_log_dir / f"{commit[:12]}-{safe_profile}-symbol.log"
    env = build_env(config, profile)
    toolchain = config.toolchain
    result = run_command(
        [
            toolchain.c_compiler,
            *toolchain.compiler_flags,
            "-shared",
            "-fPIC",
            "-g3",
            config.opt,
            "-fno-omit-frame-pointer",
            "-fno-inline",
            "-Wno-unused-function",
            "-Wno-unused-variable",
            "-Wno-incompatible-pointer-types",
            "-Wno-int-conversion",
            str(src),
            "-o",
            str(so),
        ],
        cwd=worktree,
        log_path=log_path,
        env=env,
    )
    if result.ok and matches_elf_architecture(so, config.architecture):
        log.trace("built curl symbol shared object", commit=commit, profile=profile, path=str(so), log=str(log_path))
        return True, [str(log_path)]
    log.warn("failed to build curl symbol shared object", commit=commit, profile=profile, log=str(log_path))
    return False, [str(log_path)]


def source_symbol_path(kind: str) -> str:
    return {"cookie": "lib/cookie.c", "url": "lib/url.c", "smb": "lib/smb.c"}[kind]


def compile_source_symbol_object(
    config: BuildConfig,
    worktree: Path,
    build_log_dir: Path,
    commit: str,
    profile: str,
    log: StageLogger,
) -> tuple[bool, list[str]]:
    kind = source_symbol_kind(profile)
    if kind is None:
        return False, []
    source = worktree / source_symbol_path(kind)
    if not source.exists():
        return False, []
    apply_worktree_compat_patches(worktree, log, commit)
    log_paths: list[str] = []
    boot_ok, boot_logs = run_bootstrap(config, worktree, build_log_dir, commit, profile, log)
    log_paths.extend(boot_logs)
    if not boot_ok:
        return False, log_paths
    env = build_env(config, profile)
    if not (worktree / "lib" / "curl_config.h").exists() or not (worktree / "include" / "curl" / "curlbuild.h").exists():
        host = [f"--host={config.toolchain.configure_host}"] if config.architecture == "aarch64" else []
        configure = [
            "./configure",
            *host,
            "--disable-shared",
            "--enable-static",
            *base_configure_options(),
            *idn_options_for_attempt("no-idn"),
            *ssl_options_for_attempt("no-ssl"),
        ]
        config_log = build_log_dir / f"{commit[:12]}-{path_token(profile, 'profile')}-source-config.log"
        result = run_command(configure, cwd=worktree, log_path=config_log, env=env)
        log_paths.append(str(config_log))
        if not result.ok:
            log.warn("curl source symbol configure failed", commit=commit, profile=profile, log=str(config_log))
            return False, log_paths
    outdir = worktree / ".agentic-symbols"
    outdir.mkdir(parents=True, exist_ok=True)
    safe_profile = path_token(profile, "source")
    so = outdir / f"libcurl-{safe_profile}.so"
    log_path = build_log_dir / f"{commit[:12]}-{safe_profile}-source-symbol.log"
    toolchain = config.toolchain
    flags = [
        toolchain.c_compiler,
        *toolchain.compiler_flags,
        "-shared",
        "-fPIC",
        "-g3",
        config.opt,
        "-fno-omit-frame-pointer",
        "-fno-inline",
        "-DHAVE_CONFIG_H",
        "-Wno-unused-function",
        "-Wno-unused-variable",
        "-Wno-incompatible-pointer-types",
        "-Wno-int-conversion",
        "-Wno-implicit-function-declaration",
    ]
    if kind in {"smb", "url"}:
        flags.append("-DUSE_NTLM")
    flags.extend(
        [
            "-I",
            str(worktree / "include"),
            "-I",
            str(worktree / "include" / "curl"),
            "-I",
            str(worktree / "lib"),
            str(source),
            "-o",
            str(so),
        ]
    )
    result = run_command(flags, cwd=worktree, log_path=log_path, env=env)
    log_paths.append(str(log_path))
    if result.ok and matches_elf_architecture(so, config.architecture):
        log.trace("built curl source symbol shared object", commit=commit, profile=profile, path=str(so), log=str(log_path))
        return True, log_paths
    log.warn("failed to build curl source symbol shared object", commit=commit, profile=profile, log=str(log_path))
    return False, log_paths


def vtls_mbed_polar_source(worktree: Path) -> str | None:
    mbed_path = worktree / "lib" / "vtls" / "mbedtls.c"
    polar_path = worktree / "lib" / "vtls" / "polarssl.c"
    if not mbed_path.exists() or not polar_path.exists():
        return None
    mbed_body = extract_function_source(mbed_path.read_text(encoding="utf-8", errors="replace"), "mbed_connect_step1")
    polar_body = extract_function_source(polar_path.read_text(encoding="utf-8", errors="replace"), "polarssl_connect_step1")
    if mbed_body is None or polar_body is None:
        return None
    return r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef int CURLcode;
typedef int mbedtls_ctr_drbg_context;
typedef int mbedtls_entropy_context;
typedef int mbedtls_ssl_context;
typedef int mbedtls_ssl_config;
typedef int mbedtls_x509_crt;
typedef int mbedtls_x509_crl;
typedef int mbedtls_pk_context;
typedef int x509_crt;
typedef int x509_crl;
typedef int rsa_context;
typedef int pk_context;

typedef struct {
  int unused;
} mbedtls_x509_crt_profile;

static mbedtls_x509_crt_profile mbedtls_x509_crt_profile_fr;

struct ssl_primary_config {
  int version;
  int verifypeer;
};

struct UserDefined {
  struct ssl_primary_config ssl;
  char *str[16];
  int httpversion;
};

struct SessionHandle {
  struct UserDefined set;
};

struct ssl_connect_data {
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt clicert;
  mbedtls_x509_crl crl;
  mbedtls_pk_context pk;
  mbedtls_ssl_config config;
  mbedtls_ssl_context ssl;
  rsa_context rsa;
  const char *protocols[4];
  int connecting_state;
};

struct hostname {
  char *name;
};

struct connect_bits {
  int tls_enable_alpn;
};

struct connectdata {
  struct SessionHandle *data;
  struct ssl_connect_data ssl[2];
  struct hostname host;
  int remote_port;
  int sock[2];
  struct connect_bits bits;
};

#define TRUE true
#define FALSE false
#define CURLE_OK 0
#define CURLE_SSL_CONNECT_ERROR 35
#define CURLE_SSL_CACERT_BADFILE 77
#define CURLE_SSL_CERTPROBLEM 58
#define CURLE_SSL_CRL_BADFILE 82
#define CURL_SSLVERSION_DEFAULT 0
#define CURL_SSLVERSION_TLSv1 1
#define CURL_SSLVERSION_SSLv2 2
#define CURL_SSLVERSION_SSLv3 3
#define CURL_SSLVERSION_TLSv1_0 4
#define CURL_SSLVERSION_TLSv1_1 5
#define CURL_SSLVERSION_TLSv1_2 6
#define STRING_SSL_CAFILE 0
#define STRING_SSL_CAPATH 1
#define STRING_CERT 2
#define STRING_KEY 3
#define STRING_KEY_PASSWD 4
#define STRING_SSL_CRLFILE 5
#define MBEDTLS_SSL_IS_CLIENT 0
#define MBEDTLS_SSL_TRANSPORT_STREAM 0
#define MBEDTLS_SSL_PRESET_DEFAULT 0
#define MBEDTLS_SSL_MAJOR_VERSION_3 3
#define MBEDTLS_SSL_MINOR_VERSION_0 0
#define MBEDTLS_SSL_MINOR_VERSION_1 1
#define MBEDTLS_SSL_MINOR_VERSION_2 2
#define MBEDTLS_SSL_MINOR_VERSION_3 3
#define MBEDTLS_SSL_VERIFY_OPTIONAL 0
#define MBEDTLS_PK_RSA 1
#define MBEDTLS_ERR_PK_TYPE_MISMATCH -1
#define POLARSSL_PK_RSA 1
#define POLARSSL_ERR_PK_TYPE_MISMATCH -1
#define SSL_MAJOR_VERSION_3 3
#define SSL_MINOR_VERSION_0 0
#define SSL_MINOR_VERSION_1 1
#define SSL_MINOR_VERSION_2 2
#define SSL_MINOR_VERSION_3 3
#define SSL_IS_CLIENT 0
#define SSL_VERIFY_OPTIONAL 0
#define ssl_connect_2 2
#define failf(data, ...) do { (void)(data); } while(0)
#define infof(data, ...) do { (void)(data); } while(0)

static int Curl_inet_pton(int af, const char *src, void *dst) { (void)af; (void)src; (void)dst; return 0; }
static int Curl_ssl_getsessionid(struct connectdata *conn, void **session, void *idsize) { (void)conn; (void)idsize; if(session) *session = NULL; return 1; }

static int mbedtls_entropy_func(void *ctx, unsigned char *out, size_t len) { (void)ctx; if(out) memset(out, 0, len); return 0; }
static int mbedtls_ctr_drbg_random(void *ctx, unsigned char *out, size_t len) { return mbedtls_entropy_func(ctx, out, len); }
static int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len) { (void)ctx; (void)buf; return (int)len; }
static int mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len) { (void)ctx; if(buf) memset(buf, 0, len); return 0; }
static void mbedtls_x509_crt_init(mbedtls_x509_crt *crt) { if(crt) *crt = 0; }
static int mbedtls_x509_crt_parse_file(mbedtls_x509_crt *crt, const char *path) { (void)crt; (void)path; return 0; }
static int mbedtls_x509_crt_parse_path(mbedtls_x509_crt *crt, const char *path) { (void)crt; (void)path; return 0; }
static void mbedtls_x509_crl_init(mbedtls_x509_crl *crl) { if(crl) *crl = 0; }
static int mbedtls_x509_crl_parse_file(mbedtls_x509_crl *crl, const char *path) { (void)crl; (void)path; return 0; }
static void mbedtls_pk_init(mbedtls_pk_context *pk) { if(pk) *pk = 0; }
static int mbedtls_pk_parse_keyfile(mbedtls_pk_context *pk, const char *path, const char *pwd) { (void)pk; (void)path; (void)pwd; return 0; }
static int mbedtls_pk_can_do(mbedtls_pk_context *pk, int type) { (void)pk; (void)type; return 1; }
static void mbedtls_entropy_init(mbedtls_entropy_context *ctx) { if(ctx) *ctx = 0; }
static void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context *ctx) { if(ctx) *ctx = 0; }
static int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, const unsigned char *custom, size_t len) { (void)ctx; (void)f_rng; (void)p_rng; (void)custom; (void)len; return 0; }
static void mbedtls_ssl_config_init(mbedtls_ssl_config *conf) { if(conf) *conf = 0; }
static void mbedtls_ssl_init(mbedtls_ssl_context *ssl) { if(ssl) *ssl = 0; }
static int mbedtls_ssl_setup(mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf) { (void)ssl; (void)conf; return 0; }
static int mbedtls_ssl_config_defaults(mbedtls_ssl_config *conf, int endpoint, int transport, int preset) { (void)conf; (void)endpoint; (void)transport; (void)preset; return 0; }
static void mbedtls_ssl_conf_cert_profile(mbedtls_ssl_config *conf, const mbedtls_x509_crt_profile *profile) { (void)conf; (void)profile; }
static void mbedtls_ssl_conf_min_version(mbedtls_ssl_config *conf, int major, int minor) { (void)conf; (void)major; (void)minor; }
static void mbedtls_ssl_conf_max_version(mbedtls_ssl_config *conf, int major, int minor) { (void)conf; (void)major; (void)minor; }
static void mbedtls_ssl_conf_authmode(mbedtls_ssl_config *conf, int authmode) { (void)conf; (void)authmode; }
static void mbedtls_ssl_conf_rng(mbedtls_ssl_config *conf, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) { (void)conf; (void)f_rng; (void)p_rng; }
static void mbedtls_ssl_set_bio(mbedtls_ssl_context *ssl, void *ctx, int (*send_cb)(void *, const unsigned char *, size_t), int (*recv_cb)(void *, unsigned char *, size_t), void *recv_timeout) { (void)ssl; (void)ctx; (void)send_cb; (void)recv_cb; (void)recv_timeout; }
static const int *mbedtls_ssl_list_ciphersuites(void) { static const int suites[] = { 0 }; return suites; }
static void mbedtls_ssl_conf_ciphersuites(mbedtls_ssl_config *conf, const int *suites) { (void)conf; (void)suites; }
static int mbedtls_ssl_set_session(mbedtls_ssl_context *ssl, void *session) { (void)ssl; (void)session; return 0; }
static void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config *conf, mbedtls_x509_crt *crt, mbedtls_x509_crl *crl) { (void)conf; (void)crt; (void)crl; }
static void mbedtls_ssl_conf_own_cert(mbedtls_ssl_config *conf, mbedtls_x509_crt *crt, mbedtls_pk_context *pk) { (void)conf; (void)crt; (void)pk; }
static int mbedtls_ssl_set_hostname(mbedtls_ssl_context *ssl, const char *hostname) { (void)ssl; (void)hostname; return 0; }

static int entropy_func(void *ctx, unsigned char *out, size_t len) { (void)ctx; if(out) memset(out, 0, len); return 0; }
static int ctr_drbg_random(void *ctx, unsigned char *out, size_t len) { return entropy_func(ctx, out, len); }
static int net_send(void *ctx, const unsigned char *buf, size_t len) { (void)ctx; (void)buf; return (int)len; }
static int net_recv(void *ctx, unsigned char *buf, size_t len) { (void)ctx; if(buf) memset(buf, 0, len); return 0; }
static void entropy_init(mbedtls_entropy_context *ctx) { if(ctx) *ctx = 0; }
static int ctr_drbg_init(mbedtls_ctr_drbg_context *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, const unsigned char *custom, size_t len) { (void)ctx; (void)f_rng; (void)p_rng; (void)custom; (void)len; return 0; }
static int x509_crt_parse_file(x509_crt *crt, const char *path) { (void)crt; (void)path; return 0; }
static int x509_crt_parse_path(x509_crt *crt, const char *path) { (void)crt; (void)path; return 0; }
static int x509_crl_parse_file(x509_crl *crl, const char *path) { (void)crl; (void)path; return 0; }
static void pk_init(pk_context *pk) { if(pk) *pk = 0; }
static int pk_parse_keyfile(pk_context *pk, const char *path, const char *pwd) { (void)pk; (void)path; (void)pwd; return 0; }
static int pk_can_do(pk_context *pk, int type) { (void)pk; (void)type; return 1; }
static int pk_rsa(pk_context pk) { return pk; }
static void rsa_copy(rsa_context *dst, int src) { if(dst) *dst = src; }
static void rsa_free(rsa_context *rsa) { if(rsa) *rsa = 0; }
static void pk_free(pk_context *pk) { if(pk) *pk = 0; }
static int ssl_init(mbedtls_ssl_context *ssl) { if(ssl) *ssl = 0; return 0; }
static void ssl_set_min_version(mbedtls_ssl_context *ssl, int major, int minor) { (void)ssl; (void)major; (void)minor; }
static void ssl_set_max_version(mbedtls_ssl_context *ssl, int major, int minor) { (void)ssl; (void)major; (void)minor; }
static void ssl_set_endpoint(mbedtls_ssl_context *ssl, int endpoint) { (void)ssl; (void)endpoint; }
static void ssl_set_authmode(mbedtls_ssl_context *ssl, int authmode) { (void)ssl; (void)authmode; }
static void ssl_set_rng(mbedtls_ssl_context *ssl, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) { (void)ssl; (void)f_rng; (void)p_rng; }
static void ssl_set_bio(mbedtls_ssl_context *ssl, int (*f_recv)(void *, unsigned char *, size_t), void *p_recv, int (*f_send)(void *, const unsigned char *, size_t), void *p_send) { (void)ssl; (void)f_recv; (void)p_recv; (void)f_send; (void)p_send; }
static const int *ssl_list_ciphersuites(void) { static const int suites[] = { 0 }; return suites; }
static void ssl_set_ciphersuites(mbedtls_ssl_context *ssl, const int *suites) { (void)ssl; (void)suites; }
static int ssl_set_session(mbedtls_ssl_context *ssl, void *session) { (void)ssl; (void)session; return 0; }
static void ssl_set_ca_chain(mbedtls_ssl_context *ssl, x509_crt *crt, x509_crl *crl, const char *host) { (void)ssl; (void)crt; (void)crl; (void)host; }
static void ssl_set_own_cert_rsa(mbedtls_ssl_context *ssl, x509_crt *crt, rsa_context *rsa) { (void)ssl; (void)crt; (void)rsa; }
static int ssl_set_hostname(mbedtls_ssl_context *ssl, const char *hostname) { (void)ssl; (void)hostname; return 0; }
''' + "\n" + export_curlcode_function(mbed_body) + "\n\n" + export_curlcode_function(polar_body) + "\n"


def compile_vtls_mbed_polar_symbols(config: BuildConfig, worktree: Path, build_log_dir: Path, commit: str, log: StageLogger) -> tuple[bool, list[str]]:
    source = vtls_mbed_polar_source(worktree)
    if source is None:
        return False, []
    return compile_symbol_shared(config, worktree, build_log_dir, commit, "vtls-mbed-polar", source, log)


def schannel_connect_source(worktree: Path) -> str | None:
    for rel in ("lib/vtls/curl_schannel.c", "lib/vtls/schannel.c"):
        path = worktree / rel
        if not path.exists():
            continue
        body = extract_function_source(path.read_text(encoding="utf-8", errors="replace"), "schannel_connect_step1")
        if body is None:
            continue
        return r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

typedef int CURLcode;
typedef int SECURITY_STATUS;
typedef char TCHAR;
typedef void *CredHandle;
typedef void *CtxtHandle;
typedef struct { int unused; } TimeStamp;

typedef struct {
  unsigned long cbBuffer;
  unsigned long BufferType;
  void *pvBuffer;
} SecBuffer;

typedef struct {
  unsigned long ulVersion;
  SecBuffer *pBuffers;
  unsigned long cBuffers;
} SecBufferDesc;

typedef struct {
  unsigned long dwVersion;
  unsigned long dwFlags;
  unsigned long grbitEnabledProtocols;
} SCHANNEL_CRED;

struct curl_schannel_cred {
  CredHandle cred_handle;
  TimeStamp time_stamp;
  int refcount;
  bool cached;
};

struct curl_schannel_ctxt {
  CtxtHandle ctxt_handle;
  TimeStamp time_stamp;
};

struct ssl_connect_data {
  struct curl_schannel_cred *cred;
  struct curl_schannel_ctxt *ctxt;
  unsigned long req_flags;
  unsigned long ret_flags;
  int connecting_state;
};

struct ssl_primary_config {
  int verifypeer;
  int verifyhost;
  int version;
};

struct UserDefined {
  struct ssl_primary_config ssl;
};

struct SessionHandle {
  struct UserDefined set;
};

struct hostname {
  char *name;
};

struct connectdata {
  struct SessionHandle *data;
  struct ssl_connect_data ssl[2];
  struct hostname host;
  unsigned short remote_port;
  int sock[2];
};

struct SecurityFunctionTable {
  SECURITY_STATUS (*AcquireCredentialsHandle)(void *, TCHAR *, unsigned long, void *, SCHANNEL_CRED *, void *, void *, CredHandle *, TimeStamp *);
  SECURITY_STATUS (*InitializeSecurityContext)(CredHandle *, CtxtHandle *, TCHAR *, unsigned long, unsigned long, unsigned long, SecBufferDesc *, unsigned long, CtxtHandle *, SecBufferDesc *, unsigned long *, TimeStamp *);
  SECURITY_STATUS (*FreeContextBuffer)(void *);
};

#define TRUE true
#define FALSE false
#define CURLE_OK 0
#define CURLE_OUT_OF_MEMORY 27
#define CURLE_SSL_CONNECT_ERROR 35
#define CURL_SSLVERSION_DEFAULT 0
#define CURL_SSLVERSION_TLSv1 1
#define CURL_SSLVERSION_SSLv2 2
#define CURL_SSLVERSION_SSLv3 3
#define CURL_SSLVERSION_TLSv1_0 4
#define CURL_SSLVERSION_TLSv1_1 5
#define CURL_SSLVERSION_TLSv1_2 6
#define SEC_E_OK 0
#define SEC_I_CONTINUE_NEEDED 1
#define SEC_E_WRONG_PRINCIPAL 2
#define SCHANNEL_CRED_VERSION 4
#define SCH_CRED_MANUAL_CRED_VALIDATION 0x1UL
#define SCH_CRED_IGNORE_NO_REVOCATION_CHECK 0x2UL
#define SCH_CRED_IGNORE_REVOCATION_OFFLINE 0x4UL
#define SCH_CRED_AUTO_CRED_VALIDATION 0x8UL
#define SCH_CRED_REVOCATION_CHECK_CHAIN 0x10UL
#define SCH_CRED_NO_SERVERNAME_CHECK 0x20UL
#define SP_PROT_TLS1_0_CLIENT 0x40UL
#define SP_PROT_TLS1_1_CLIENT 0x80UL
#define SP_PROT_TLS1_2_CLIENT 0x100UL
#define SP_PROT_SSL3_CLIENT 0x200UL
#define SP_PROT_SSL2_CLIENT 0x400UL
#define SECPKG_CRED_OUTBOUND 2UL
#define SECBUFFER_EMPTY 0UL
#define SECBUFFER_VERSION 0UL
#define ISC_REQ_SEQUENCE_DETECT 0x1UL
#define ISC_REQ_REPLAY_DETECT 0x2UL
#define ISC_REQ_CONFIDENTIALITY 0x4UL
#define ISC_REQ_ALLOCATE_MEMORY 0x8UL
#define ISC_REQ_STREAM 0x10UL
#define ssl_connect_2 2
#define UNISP_NAME "UNISP"
#define failf(data, ...) do { (void)(data); } while(0)
#define infof(data, ...) do { (void)(data); } while(0)
#define Curl_safefree(ptr) do { free(ptr); (ptr) = NULL; } while(0)

static SECURITY_STATUS stub_acquire(void *principal, TCHAR *package, unsigned long credential_use, void *logon_id, SCHANNEL_CRED *auth_data, void *get_key_fn, void *get_key_arg, CredHandle *cred, TimeStamp *expiry) {
  (void)principal; (void)package; (void)credential_use; (void)logon_id; (void)auth_data; (void)get_key_fn; (void)get_key_arg; (void)expiry;
  if(cred) *cred = malloc(1);
  return SEC_E_OK;
}

static SECURITY_STATUS stub_initialize(CredHandle *cred, CtxtHandle *oldctx, TCHAR *target, unsigned long req, unsigned long reserved1, unsigned long datarep, SecBufferDesc *input, unsigned long reserved2, CtxtHandle *newctx, SecBufferDesc *output, unsigned long *attrs, TimeStamp *expiry) {
  (void)cred; (void)oldctx; (void)target; (void)req; (void)reserved1; (void)datarep; (void)input; (void)reserved2; (void)expiry;
  if(newctx) *newctx = malloc(1);
  if(attrs) *attrs = req;
  if(output && output->pBuffers && output->cBuffers) {
    output->pBuffers[0].cbBuffer = 0;
    output->pBuffers[0].pvBuffer = NULL;
  }
  return SEC_I_CONTINUE_NEEDED;
}

static SECURITY_STATUS stub_free_context(void *ptr) { free(ptr); return SEC_E_OK; }
static struct SecurityFunctionTable stub_table = { stub_acquire, stub_initialize, stub_free_context };
static struct SecurityFunctionTable *s_pSecFn = &stub_table;

static void InitSecBuffer(SecBuffer *buffer, unsigned long BufType, void *BufDataPtr, unsigned long BufByteSize) {
  buffer->cbBuffer = BufByteSize;
  buffer->BufferType = BufType;
  buffer->pvBuffer = BufDataPtr;
}

static void InitSecBufferDesc(SecBufferDesc *desc, SecBuffer *BufArr, unsigned long NumArrElem) {
  desc->ulVersion = SECBUFFER_VERSION;
  desc->pBuffers = BufArr;
  desc->cBuffers = NumArrElem;
}

static int Curl_ssl_getsessionid(struct connectdata *conn, void **session, void *idsize) { (void)conn; (void)idsize; if(session) *session = NULL; return 1; }
static const char *Curl_sspi_strerror(struct connectdata *conn, SECURITY_STATUS status) { (void)conn; (void)status; return "agentic schannel stub"; }
static int Curl_inet_pton(int af, const char *src, void *dst) { (void)af; (void)src; (void)dst; return 0; }
static TCHAR *Curl_convert_UTF8_to_tchar(const char *input) {
  size_t len = input ? strlen(input) : 0;
  TCHAR *out = malloc(len + 1);
  if(out) {
    if(len) memcpy(out, input, len);
    out[len] = 0;
  }
  return out;
}
static void Curl_unicodefree(void *ptr) { free(ptr); }
static CURLcode Curl_write_plain(struct connectdata *conn, int sockfd, const void *mem, size_t len, ssize_t *written) {
  (void)conn; (void)sockfd; (void)mem;
  if(written) *written = (ssize_t)len;
  return CURLE_OK;
}
''' + "\n" + export_curlcode_function(body) + "\n"
    return None


def compile_schannel_connect_symbol(config: BuildConfig, worktree: Path, build_log_dir: Path, commit: str, log: StageLogger) -> tuple[bool, list[str]]:
    source = schannel_connect_source(worktree)
    if source is None:
        return False, []
    return compile_symbol_shared(config, worktree, build_log_dir, commit, "schannel-connect", source, log)


def schannel_wince_source(worktree: Path) -> str | None:
    body = extract_function_source((worktree / "lib" / "vtls" / "schannel.c").read_text(encoding="utf-8", errors="replace"), "verify_certificate")
    if body is None:
        return None
    body = body.replace("static CURLcode verify_certificate", "CURLcode verify_certificate")
    return r'''
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int CURLcode;
typedef int SECURITY_STATUS;
typedef unsigned long DWORD;
typedef char TCHAR;
typedef struct { int hCertStore; } CERT_CONTEXT;
typedef struct { DWORD dwErrorStatus; } CERT_TRUST_STATUS;
typedef struct { CERT_TRUST_STATUS TrustStatus; } CERT_SIMPLE_CHAIN;
typedef struct { CERT_SIMPLE_CHAIN **rgpChain; } CERT_CHAIN_CONTEXT;
typedef struct { DWORD cbSize; } CERT_CHAIN_PARA;
typedef struct { int ctxt_handle; } CtxtHandle;
struct curl_schannel_ctxt { CtxtHandle ctxt_handle; };
struct ssl_connect_data { struct curl_schannel_ctxt *ctxt; };
struct ssl_primary_config { int no_revoke; };
struct UserDefined { struct ssl_primary_config ssl; };
struct Curl_easy { struct UserDefined set; };
struct hostname { char *name; };
struct ssl_config_data { int verifyhost; };
struct connectdata {
  struct Curl_easy *data;
  struct ssl_connect_data ssl[2];
  struct ssl_config_data ssl_config;
  struct hostname host;
  struct { struct hostname host; } http_proxy;
};
struct SecurityFunctionTable {
  SECURITY_STATUS (*QueryContextAttributes)(CtxtHandle *, DWORD, CERT_CONTEXT **);
};
#define CURLE_OK 0
#define CURLE_PEER_FAILED_VERIFICATION 51
#define CURLE_OUT_OF_MEMORY 27
#define SEC_E_OK 0
#define SECPKG_ATTR_REMOTE_CERT_CONTEXT 83
#define CERT_CHAIN_REVOCATION_CHECK_CHAIN 0x20000000UL
#define CERT_TRUST_IS_NOT_TIME_NESTED 0x00000002UL
#define CERT_TRUST_IS_REVOKED 0x00000004UL
#define CERT_TRUST_IS_PARTIAL_CHAIN 0x00010000UL
#define CERT_TRUST_IS_UNTRUSTED_ROOT 0x00000020UL
#define CERT_TRUST_IS_NOT_TIME_VALID 0x00000001UL
#define CERT_NAME_DNS_TYPE 6
#define CERT_NAME_DISABLE_IE4_UTF8_FLAG 0x00010000UL
#define CURL_HOST_MATCH 1
#define SSL_IS_PROXY() 0
static SECURITY_STATUS stub_query(CtxtHandle *handle, DWORD attr, CERT_CONTEXT **cert) { (void)handle; (void)attr; if(cert) *cert = NULL; return 1; }
static struct SecurityFunctionTable stub_table = { stub_query };
static struct SecurityFunctionTable *s_pSecFn = &stub_table;
static const char *Curl_sspi_strerror(struct connectdata *conn, SECURITY_STATUS status) { (void)conn; (void)status; return "agentic schannel stub"; }
static DWORD GetLastError(void) { return 1; }
static int CertGetCertificateChain(void *engine, CERT_CONTEXT *cert, void *time, int store, CERT_CHAIN_PARA *para, DWORD flags, void *reserved, const CERT_CHAIN_CONTEXT **ctx) { (void)engine; (void)cert; (void)time; (void)store; (void)para; (void)flags; (void)reserved; if(ctx) *ctx = NULL; return 0; }
static DWORD CertGetNameString(CERT_CONTEXT *cert, DWORD type, DWORD flags, void *param, TCHAR *buf, DWORD size) { (void)cert; (void)type; (void)flags; (void)param; if(buf && size) *buf = 0; return 0; }
static void CertFreeCertificateChain(const CERT_CHAIN_CONTEXT *ctx) { (void)ctx; }
static void CertFreeCertificateContext(CERT_CONTEXT *ctx) { (void)ctx; }
static char *Curl_convert_UTF8_to_tchar(const char *input) { return input ? strdup(input) : NULL; }
static const char *Curl_convert_tchar_to_UTF8(const TCHAR *input) { return input ? strdup(input) : NULL; }
static void Curl_unicodefree(const void *ptr) { free((void *)ptr); }
static int Curl_cert_hostcheck(const char *pattern, const char *hostname) { return pattern && hostname && !strcmp(pattern, hostname) ? CURL_HOST_MATCH : 0; }
static int _tcsicmp(const TCHAR *a, const TCHAR *b) { return strcasecmp(a ? a : "", b ? b : ""); }
#define failf(data, ...) do { (void)(data); } while(0)
#define infof(data, ...) do { (void)(data); } while(0)
typedef union {
  char *tchar_ptr;
  const char *const_tchar_ptr;
} xcharp_u;
''' + "\n" + body + "\n"


def compile_schannel_wince_symbol(config: BuildConfig, worktree: Path, build_log_dir: Path, commit: str, log: StageLogger) -> tuple[bool, list[str]]:
    outdir = worktree / ".agentic-symbols"
    outdir.mkdir(parents=True, exist_ok=True)
    src = outdir / "schannel_wince_verify_certificate.c"
    so = outdir / "libcurl-schannel-wince.so"
    source = schannel_wince_source(worktree)
    if source is None:
        return False, []
    src.write_text(source, encoding="utf-8")
    log_path = build_log_dir / f"{commit[:12]}-schannel-wince-symbol.log"
    env = build_env(config, "schannel-wince")
    toolchain = config.toolchain
    result = run_command(
        [
            toolchain.c_compiler,
            *toolchain.compiler_flags,
            "-shared",
            "-fPIC",
            "-g3",
            config.opt,
            "-fno-omit-frame-pointer",
            "-fno-inline",
            str(src),
            "-o",
            str(so),
        ],
        cwd=worktree,
        log_path=log_path,
        env=env,
    )
    if result.ok and matches_elf_architecture(so, config.architecture):
        log.trace("built curl schannel WinCE symbol object", commit=commit, path=str(so), log=str(log_path))
        return True, [str(log_path)]
    log.warn("failed to build curl schannel WinCE symbol object", commit=commit, log=str(log_path))
    return False, [str(log_path)]


def write_build_marker(config: BuildConfig, worktree: Path, profile: str) -> None:
    build_marker_path(worktree, profile).write_text(build_signature(config, profile), encoding="utf-8")


def has_build_marker(config: BuildConfig, worktree: Path, profile: str) -> bool:
    try:
        return build_marker_path(worktree, profile).read_text(encoding="utf-8") == build_signature(config, profile)
    except OSError:
        return False


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
    # Archived backends have their own signature inside the registered worktree.
    for parent in resolved.parents:
        for marker in sorted(parent.glob(".agentic-build-*.marker")):
            metadata = read_marker(marker)
            if metadata.get("adapter") == ADAPTER_VERSION:
                return metadata
        if parent == worktree:
            break
    return {}


def expected_elf(path: Path, architecture: str = "") -> bool:
    if not is_elf(path):
        return False
    return not architecture or matches_elf_architecture(path, architecture)


def has_built_curl(
    worktree: Path,
    profile: str,
    config: BuildConfig | None = None,
    *,
    require_marker: bool = True,
) -> bool:
    architecture = config.architecture if config is not None else build_metadata(worktree, profile).get("architecture", "")
    candidates = candidates_for_binary(worktree, profile=profile, architecture=architecture)
    # Only explicit GnuTLS profiles use the archived backend as their primary.
    if not wants_gnutls(profile):
        candidates = [(path, name) for path, name in candidates
                      if ".agentic-gnutls" not in path.relative_to(worktree).parts]
    if wants_gnutls(profile):
        nm = config.toolchain.nm if config else build_metadata(worktree, profile).get("nm", "")
        backend_symbols = {"gtls_connect_step3", "Curl_gtls_connect", "Curl_ssl_gnutls"}
        candidates = [(path, name) for path, name in candidates
                      if nm and symbol_names(path, nm) & backend_symbols]
    built = bool(candidates)
    if not built or config is None:
        return built
    return not require_marker or has_build_marker(config, worktree, profile)


def compile_commit(config: BuildConfig, ref: str, stage: str, log: StageLogger, profile: str = "static") -> BuildOutput:
    if wants_gnutls(profile) and config.architecture != "x86_64":
        return BuildOutput(ref, Path(), False, [], "GnuTLS requires target development packages not supplied by the cross contract")
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
    build_log_dir = current_log_root(config.output) / "trace" / f"{stage}_builds"
    if wants_gnutls(profile):
        source = worktree / ".agentic-gnutls"
        if has_built_curl(source, profile, config):
            write_build_marker(config, worktree, profile)
            return BuildOutput(commit, worktree, True, [], "reused existing GnuTLS build")
        probe_log = build_log_dir / f"{commit[:12]}-{build_token(config, profile)}-dependency-probe.log"
        if not probe_gnutls(config, worktree, probe_log, build_env(config)):
            return BuildOutput(commit, worktree, False, [str(probe_log)], "GnuTLS dependency probe failed")
        source, source_logs = prepare_gnutls_source(worktree, commit, build_log_dir, profile)
        logs = [str(probe_log), *source_logs]
        if source is None:
            return BuildOutput(commit, worktree, False, logs, "GnuTLS source preparation failed")
        built = compile_worktree(config, source, commit, stage, log, profile, build_log_dir)
        logs.extend(built.log_paths)
        if built.ok:
            # Public APIs receive the registered root, not the archived source.
            write_build_marker(config, worktree, profile)
            remove_build_logs(config, logs, log, success=True, reason=f"{stage} GnuTLS build completed")
        return BuildOutput(commit, worktree, built.ok, logs, built.notes)
    return compile_worktree(config, worktree, commit, stage, log, profile, build_log_dir)


def compile_worktree(
    config: BuildConfig, worktree: Path, commit: str, stage: str, log: StageLogger,
    profile: str, build_log_dir: Path,
) -> BuildOutput:
    """Run one profile in an already isolated source tree."""
    log_paths: list[str] = []
    if has_built_curl(worktree, profile, config):
        log.trace("reuse built curl worktree", commit=commit, profile=profile, worktree=str(worktree))
        return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths, notes="reused existing build")

    if wants_schannel_wince(profile):
        ok, symbol_logs = compile_schannel_wince_symbol(config, worktree, build_log_dir, commit, log)
        log_paths.extend(symbol_logs)
        if ok:
            write_build_marker(config, worktree, profile)
            remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} schannel WinCE symbol build completed")
            return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths)
        return BuildOutput(commit=commit, worktree=worktree, ok=False, log_paths=log_paths, notes="schannel WinCE symbol build failed")
    if wants_vtls_mbed_polar(profile):
        ok, symbol_logs = compile_vtls_mbed_polar_symbols(config, worktree, build_log_dir, commit, log)
        log_paths.extend(symbol_logs)
        if ok:
            write_build_marker(config, worktree, profile)
            remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} mbedTLS/PolarSSL symbol build completed")
            return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths)
        return BuildOutput(commit=commit, worktree=worktree, ok=False, log_paths=log_paths, notes="mbedTLS/PolarSSL symbol build failed")
    if wants_schannel_connect(profile):
        ok, symbol_logs = compile_schannel_connect_symbol(config, worktree, build_log_dir, commit, log)
        log_paths.extend(symbol_logs)
        if ok:
            write_build_marker(config, worktree, profile)
            remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} Schannel connect symbol build completed")
            return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths)
        return BuildOutput(commit=commit, worktree=worktree, ok=False, log_paths=log_paths, notes="Schannel connect symbol build failed")
    if wants_source_symbol(profile):
        ok, symbol_logs = compile_source_symbol_object(config, worktree, build_log_dir, commit, profile, log)
        log_paths.extend(symbol_logs)
        if ok:
            write_build_marker(config, worktree, profile)
            remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} source symbol build completed")
            return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths)
        return BuildOutput(commit=commit, worktree=worktree, ok=False, log_paths=log_paths, notes="source symbol build failed")

    apply_worktree_compat_patches(worktree, log, commit)
    boot_ok, boot_logs = run_bootstrap(config, worktree, build_log_dir, commit, profile, log)
    log_paths.extend(boot_logs)
    if not boot_ok:
        cmake_ok, cmake_logs = compile_cmake_fallback(config, worktree, build_log_dir, commit, profile, log)
        log_paths.extend(cmake_logs)
        if cmake_ok:
            write_build_marker(config, worktree, profile)
            remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} cmake fallback build completed")
            return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths, notes="built with cmake fallback after bootstrap failed")
        return BuildOutput(commit=commit, worktree=worktree, ok=False, log_paths=log_paths, notes="bootstrap failed; cmake fallback failed")

    env = build_env(config, profile)
    for index, configure in enumerate(configure_commands(config, profile, worktree), start=1):
        clean_log = make_clean(worktree, build_log_dir, commit, profile, index, env)
        if clean_log:
            log_paths.append(clean_log)
        configure_log = build_log_dir / f"{commit[:12]}-{path_token(profile, 'profile')}-config-{index}.log"
        result = run_command(configure, cwd=worktree, log_path=configure_log, env=env)
        log_paths.append(str(configure_log))
        if not result.ok:
            log.warn("curl configure failed", commit=commit, profile=profile, command=configure, log=str(configure_log))
            continue
        ok = False
        for make_index, make in enumerate(make_commands(worktree, env), start=1):
            target = make[make.index("-C") + 1] if "-C" in make else "all"
            make_log = build_log_dir / f"{commit[:12]}-{path_token(profile, 'profile')}-{index}-{make_index}-{target}.log"
            result = run_command(make, cwd=worktree, log_path=make_log, env=env)
            log_paths.append(str(make_log))
            if has_built_curl(worktree, profile, config, require_marker=False):
                if not result.ok:
                    log.warn(
                        "curl make returned nonzero after producing an ELF candidate",
                        commit=commit,
                        profile=profile,
                        command=make,
                        log=str(make_log),
                    )
                ok = True
                break
            if not result.ok:
                log.warn("curl make failed", commit=commit, profile=profile, command=make, log=str(make_log))
        if ok:
            write_build_marker(config, worktree, profile)
            log.trace("curl commit built", commit=commit, profile=profile, worktree=str(worktree), logs=log_paths)
            remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} build completed")
            return BuildOutput(commit=commit, worktree=worktree, ok=True, log_paths=log_paths)
    cmake_ok, cmake_logs = compile_cmake_fallback(config, worktree, build_log_dir, commit, profile, log)
    log_paths.extend(cmake_logs)
    if cmake_ok:
        write_build_marker(config, worktree, profile)
        remove_build_logs(config, log_paths, log, success=True, reason=f"{stage} cmake fallback build completed")
        return BuildOutput(
            commit=commit,
            worktree=worktree,
            ok=True,
            log_paths=log_paths,
            notes="built with cmake fallback after autotools attempts failed",
        )
    return BuildOutput(commit=commit, worktree=worktree, ok=False, log_paths=log_paths, notes="all autotools and cmake build commands failed")


def classify_binary(path: Path) -> str:
    name = path.name
    if name.startswith("libcurl-") and (name.endswith(".so") or ".so." in name):
        return "libcurl"
    if name == "curl" or name == "lt-curl":
        return "curl"
    if name.startswith("libcurl") or name.startswith("cygcurl"):
        return "libcurl"
    parent_name = path.parent.name
    if parent_name == "src" and name.startswith("curl"):
        return "curl"
    return path.stem


def candidate_sort_key(item: tuple[Path, str], profile: str) -> tuple[int, int, str]:
    path, name = item
    if profile_kind(profile) == "shared":
        rank = {"libcurl": 0, "curl": 1}.get(name, 2)
    else:
        rank = {"curl": 0, "libcurl": 1}.get(name, 2)
    depth_rank = 0 if ".libs" in path.parts else 1
    return rank, depth_rank, str(path)


def candidates_for_binary(worktree: Path, profile: str = "static", architecture: str = "") -> list[tuple[Path, str]]:
    patterns = [
        ".agentic-symbols/libcurl*.so*",
        "lib/.libs/libcurl.so*",
        "lib/.libs/cygcurl*.dll",
        "lib/libcurl.so*",
        "src/.libs/curl",
        "src/.libs/lt-curl",
        "src/curl",
        "build/src/curl",
        "build/src/*curl*",
    ]
    found: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in sorted(worktree.glob(pattern)):
            try:
                key = path.resolve()
            except OSError:
                key = path
            if key in seen or not path.is_file() or not expected_elf(path, architecture):
                continue
            seen.add(key)
            found.append((path, classify_binary(path)))
    for path in sorted(worktree.rglob("libcurl.so*")):
        try:
            key = path.resolve()
        except OSError:
            key = path
        if key in seen or not path.is_file() or not expected_elf(path, architecture):
            continue
        seen.add(key)
        found.append((path, "libcurl"))
    for path in sorted(worktree.rglob("curl")):
        try:
            key = path.resolve()
        except OSError:
            key = path
        if key in seen or not path.is_file() or not expected_elf(path, architecture):
            continue
        seen.add(key)
        found.append((path, "curl"))
    companion = worktree / ".agentic-gnutls"
    companion_profile = profile if wants_gnutls(profile) else f"{profile}-gnutls"
    companion_metadata = build_metadata(companion, companion_profile)
    expected_metadata = build_metadata(worktree, profile)
    if expected_metadata:
        expected_metadata = {**expected_metadata, "profile": companion_profile}
    companion_valid = (
        companion_metadata.get("adapter") == ADAPTER_VERSION
        and companion_metadata.get("profile") == companion_profile
        and (not architecture or companion_metadata.get("architecture") == architecture)
        and companion_metadata == expected_metadata
    )
    qualified: list[tuple[Path, str]] = []
    for path, name in found:
        if ".agentic-gnutls" in path.relative_to(worktree).parts:
            if not companion_valid:
                continue
            name = f"{name}-gnutls"
        elif wants_gnutls(profile):
            name = f"{name}-gnutls"
        qualified.append((path, name))
    return sorted(qualified, key=lambda item: candidate_sort_key(item, profile))


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
    if architecture == "aarch64":
        readelf = metadata.get("readelf", "")
        return bool(readelf) and readelf_machine(path, readelf) == "AArch64"
    return True


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
