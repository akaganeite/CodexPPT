# tcpdump compile adapter

Adapter: `binarybuild/compile/tcpdump.py`

Public APIs:
- `compile_commit(config, ref, stage, log, profile="static") -> BuildOutput`
- `choose_binary(worktree, functions, preferred="", profile="static") -> BinaryMatch | None`
- `find_binary_by_name(worktree, binary_name, profile="static") -> Path | None`
- `copy_binary(src, dest) -> None`
- `target_filename(project, version, binary_name, compiler="", opt="") -> str`

Build strategy:
- Resolves the requested ref in the source repository and creates a detached git worktree under `config.worktree_root`.
- Does not configure or compile in the user's source repository checkout. Build outputs are created inside detached worktrees and `.agentic-build-*` directories under the output root.
- Worktree names include commit, profile, compiler, optimization flag, and adapter version tokens so incremental runs do not reuse incompatible builds.
- Sets `CC` from `config.compiler` and builds with debug-friendly C flags: `-g3`, requested optimization, `-fcommon`, `-fno-omit-frame-pointer`, `-fno-inline`, and non-fatal warning flags. `-fcommon` helps older releases compile with modern GCC.
- Uses `MAKEINFO=true` and `YACC="bison -y"` defaults to avoid common optional tool failures.
- The primary path is Autoconf. If `configure` is absent and `autogen.sh` exists, the adapter runs `sh autogen.sh` in the detached worktree, then configures out of tree.
- Autoconf configure attempts prefer system libpcap and SMB printer support so CVE-related functions such as `smb_fdata1` remain present. Attempts start with `--with-system-libpcap --without-crypto --enable-smb --disable-universal`, then relax optional flags if older releases reject or fail with them.
- CMake is a fallback for releases with `CMakeLists.txt`. It configures out of tree with `CMAKE_BUILD_TYPE=Debug`, the requested C compiler, and first tries SMB enabled with crypto disabled before relaxing to default CMake options.
- Build attempts target the `tcpdump` executable directly when possible, then fall back to the default build target.
- A build is complete only after an ELF candidate named `tcpdump` exists. Successful builds write an adapter/compiler/opt/profile marker and may have detailed build logs removed by `config.cleanup_build_logs`; failed logs are retained.

Binary selection:
- Candidate search covers `.agentic-build-<profile>-autoconf-*`, `.agentic-build-<profile>-cmake-*`, `.agentic-build-<profile>`, and the detached worktree.
- The stable binary name is `tcpdump`.
- `choose_binary` uses `nm` and `nm -D`, strips symbol version suffixes, and returns the candidate containing all requested functions when possible. If no complete match exists, it returns the candidate with the fewest missing functions.

Expected CVE coverage:
- The reference-build CVEs listed for tcpdump all build into the `tcpdump` executable.
- Changed-function matching should normally resolve `ppp_hdlc`, `pretty_print_packet`, time formatting helpers, SMB helpers, BGP parsers, White Board helpers, IKE parsers, RPKI-RTR, BOOTP, PKTAP, LMP, LLDP, NetBIOS, EIGRP, NFS, and address-string helpers to the `tcpdump` ELF.
