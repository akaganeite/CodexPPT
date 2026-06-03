# Binutils Stripped O0 Unbounded Run: Address Localization Summary

- Raw dir: `/home/zhangxb/ClawSpace/agent/straight_detect/runs/binutils_stripped_o0_unbounded_raw`
- CVE count: 95
- Scope: each CVE is summarized by how Codex used lightweight binutils/tool calls to localize candidate patch-related address ranges. This does not analyze the final local objdump semantics.
- Note: this report reflects the observed run, including any path-isolation mistakes in that run.

## CVE-2014-8484

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `byte count|Bad checksum|S-record|S-records|too small; byte count|Bad checksum|S-record|S-records|too small`。随后 objdump+rg 用模式 `1c2700|1c2728|1c26c8; 1c82c0|1c82e8|1c8288` 将锚点关联到地址簇 0xcbbbb, 0xcbbbd, 0xcbbc0, 0xce20c, 0xce20e, 0xce211。据此把后续反汇编收敛到窗口 binutils-2.25-o0-objdump:0xcbf00-0xcc520, binutils-2.25.1-o0-objdump:0xce500-0xceb80, binutils-2.26-o0-objdump:0xc9900-0xc9f80, binutils-2.24-o0-objdump:0xc3150-0xc3520。

Windows: `binutils-2.25-o0-objdump:0xcbf00-0xcc520`; `binutils-2.25.1-o0-objdump:0xce500-0xceb80`; `binutils-2.26-o0-objdump:0xc9900-0xc9f80`; `binutils-2.24-o0-objdump:0xc3150-0xc3520`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.24-o0-objdump | head -40'` | strings cmd: `/bin/zsh -lc 'strings -a -t x binutils-2.24-o0-objdump | rg -n "byte count|Bad checksum|S-record|S-records|too small"'` | xref cmd: `/bin/zsh -lc 'objdump -d -Mintel binutils-2.25-o0-objdump | rg "1c2700|1c2728|1c26c8" -C 5'`

## CVE-2014-8485

readelf/nm 先查符号或导入模式 `setup_group|bfd_alloc2|bfd_bread|bfd_seek|memset|bfd_set_error|_bfd_error_handler`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1a8668 %B: Corrupt size field in group section header: 0x%lx; 1a869e %B: invalid SHT_GROUP entry; 1c5168 %B: corrupt size field in group section header: 0x%lx`。随后 objdump+rg 用模式 `1a8668|1a869e|1a86c0; 1c5168|1c51a0|1c51d6|1c51f8|1c5220` 将锚点关联到地址簇 0xe442d, 0xe4430, 0xe4432, 0xef055, 0xef058, 0xef05a。据此把后续反汇编收敛到窗口 binutils-2.24-o0-objdump:0xe4430-0xe4498, binutils-2.24-o0-objdump:0xe4800-0xe4870。

Windows: `binutils-2.24-o0-objdump:0xe4430-0xe4498`; `binutils-2.24-o0-objdump:0xe4800-0xe4870`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.24-o0-objdump binutils-2.23.2-o0-objdump binutils-2.23.1-o0-objdump binutils-2.25-o0-objdump binutils-2.25.1-o0-obj...` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.24-o0-objdump | rg 'group section header|no valid group|no group info|invalid SHT_GROUP'"` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.24-o0-objdump | rg -B5 -A12 '1a8668|1a869e|1a86c0'"`

## CVE-2014-8738

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `185f78 badly formed extended line op encountered!; 189a08   DW_CFA_offset_extended: %s%s at cfa%+ld; 1a2018 Badly formed extended line op encountered!`。随后 objdump+rg 用模式 `1a3e59|1a3e6a|18ee56; 1c0809|1c081a|1ab1d6` 将锚点关联到地址簇 0x9c37e, 0x18ee56, 0xa9c11, 0xa47b2, 0x1ab1d6, 0xb2277。据此把后续反汇编收敛到窗口 binutils-2.24-o0-objdump:0xa9b80-0xa9f80, binutils-2.25-o0-objdump:0xb21e0-0xb2600, binutils-2.24-o0-objdump:0xa9ca0-0xa9d20, binutils-2.25.1-o0-objdump:0xb4600-0xb49c0, binutils-2.26-o0-objdump:0xb7de0-0xb81c0。

Windows: `binutils-2.24-o0-objdump:0xa9b80-0xa9f80`; `binutils-2.25-o0-objdump:0xb21e0-0xb2600`; `binutils-2.24-o0-objdump:0xa9ca0-0xa9d20`; `binutils-2.25.1-o0-objdump:0xb4600-0xb49c0`; `binutils-2.26-o0-objdump:0xb7de0-0xb81c0`; `binutils-2.25-o0-objdump:0xb22f0-0xb23b0`

Trace: strings cmd: `/bin/zsh -lc "strings -tx binutils-2.24-o0-objdump | rg 'ARFILENAMES|// |malformed|extended'"` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.24-o0-objdump | rg '1a3e59|1a3e6a|18ee56'"`

## CVE-2017-12448

readelf/nm 先查符号或导入模式 `"`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1e4b74 /SYM64/; 1fba9e !<thin>`。随后 objdump+rg 用模式 `1e9dfe|1e9e07|1e9e10; 1faa7e|1faa87|1faa90` 将锚点关联到地址簇 0x92147, 0x1e9dfe, 0x92162, 0x98331, 0x1faa7e, 0x98346。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0xb7828-0xb7900, binutils-2.29-o0-objdump:0xbf5f0-0xbf6c8, binutils-2.27-o0-objdump:0xb70f5-0xb71cd, binutils-2.29.1-o0-objdump:0xbf5a9-0xbf695, binutils-2.30-o0-objdump:0xc57df-0xc58c0。

Windows: `binutils-2.28-o0-objdump:0xb7828-0xb7900`; `binutils-2.29-o0-objdump:0xbf5f0-0xbf6c8`; `binutils-2.27-o0-objdump:0xb70f5-0xb71cd`; `binutils-2.29.1-o0-objdump:0xbf5a9-0xbf695`; `binutils-2.30-o0-objdump:0xc57df-0xc58c0`; `binutils-2.31-o0-objdump:0xb4ce5-0xb4db0`

Trace: symbol/import cmd: `/bin/zsh -lc "for f in binutils-2.29-o0-objdump binutils-2.28-o0-objdump binutils-2.27-o0-objdump binutils-2.29.1-o0-objdump binutils-2.30-o0-objdump bi...` | strings cmd: `/bin/zsh -lc "for f in binutils-2.29-o0-objdump binutils-2.28-o0-objdump binutils-2.27-o0-objdump binutils-2.29.1-o0-objdump binutils-2.30-o0-objdump bi...` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.28-o0-objdump | rg -n '1e9dfe|1e9e07|1e9e10' -C 8"`

## CVE-2017-12799

readelf/nm 先查符号或导入模式 `elf_read_notes|bfd_malloc|bfd_bread|elf_parse_notes|sprintf|strlen; elf_read_notes|bfd_malloc|bfd_bread|elf_parse_notes|sprintf|strlen`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d7afd                                   The STYLE, if specified, can be `auto', `gnu',; 1d7b4e                                   `lucid', `arm', `hp', `edg', `gnu-v3', `java'; 126b getpagesize`。随后 objdump+rg 用模式 `cmp.*0xffffffffffffffff|cmp.*0xff|add.*0x1|test.*rax|bfd_malloc|call; cmp.*0xffffffffffffffff|cmp.*0xff|add.*0x1|test.*rax|bfd_malloc|call` 将锚点关联到地址簇 0x47874, 0x47881, 0x47887, 0x141731, 0x141768, 0x141778。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x1d6460-0x1d6690, binutils-2.29.1-o0-objdump:0x1d6ea0-0x1d7100。

Windows: `binutils-2.29-o0-objdump:0x1d6460-0x1d6690`; `binutils-2.29.1-o0-objdump:0x1d6ea0-0x1d7100`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.29-o0-objdump | rg 'elf_read_notes|bfd_malloc|bfd_bread|elf_parse_notes|sprintf|strlen'"` | strings cmd: `/bin/zsh -lc "strings -t x binutils-2.29-o0-objdump | rg -i 'note|GNU|corrupt|invalid' | head -100"` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.29-o0-objdump | rg -n "cmp.*0xffffffffffffffff|cmp.*0xff|add.*0x1|test.*rax|bfd_malloc|call"'`

## CVE-2017-12967

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1824138   -t, --syms               Display the contents of the symbol table(s); 1824209   -T, --dynamic-syms       Display the contents of the dynamic symbol table; 1938826   -t, --syms               Display the contents of the symbol table(s)`。未看到明确 objdump+rg 粗定位，模型直接进入局部窗口或停在符号/字符串级定位。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x150000-0x160000, binutils-2.29-o0-objdump:0xd5c30-0xd5d10, binutils-2.29.1-o0-objdump:0xd5c30-0xd5d30, binutils-2.30-o0-objdump:0xdc260-0xdc340, binutils-2.31-o0-objdump:0xcb730-0xcb810。

Windows: `binutils-2.29-o0-objdump:0x150000-0x160000`; `binutils-2.29-o0-objdump:0xd5c30-0xd5d10`; `binutils-2.29.1-o0-objdump:0xd5c30-0xd5d30`; `binutils-2.30-o0-objdump:0xdc260-0xdc340`; `binutils-2.31-o0-objdump:0xcb730-0xcb810`

Trace: strings cmd: `/bin/zsh -lc "strings -a -td binutils-2.31-o0-objdump | rg -i 'tek|hex|symbol|record|invalid|corrupt'"`

## CVE-2017-13710

strings 找字符串锚点 `1fee08 %B: corrupt size field in group section header: %#Lx; 1fee40 %B: invalid size field in group section header: %#Lx; 1ffe48 %B: corrupt size field in group section header: %#Lx`。随后 objdump+rg 用模式 `1feec0|1fee98|1fee75|1fee40|1fee08; 1fff00|1fff28|1ffed8|1ffeb5|1ffe80|1ffe48` 将锚点关联到地址簇 0x148044, 0x1fee08, 0x148090, 0x148216, 0x1ffe48, 0x148262。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0xf0600-0xf0780, binutils-2.29.1-o0-objdump:0xf0780-0xf0b20, binutils-2.30-o0-objdump:0xf7060-0xf7420, binutils-2.31-o0-objdump:0xe6bd0-0xe6fa0, binutils-2.29-o0-objdump:0xf03e0-0xf06b5。

Windows: `binutils-2.29-o0-objdump:0xf0600-0xf0780`; `binutils-2.29.1-o0-objdump:0xf0780-0xf0b20`; `binutils-2.30-o0-objdump:0xf7060-0xf7420`; `binutils-2.31-o0-objdump:0xe6bd0-0xe6fa0`; `binutils-2.29-o0-objdump:0xf03e0-0xf06b5`

Trace: strings cmd: `/bin/zsh -lc 'strings -a -tx binutils-2.29-o0-objdump | rg "group section|no group info|SHT_GROUP|no valid group|corrupt size field|invalid size field"'` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.29-o0-objdump | rg -n "1feec0|1fee98|1fee75|1fee40|1fee08"'`

## CVE-2017-13757

readelf/nm 先查符号或导入模式 `elf_(i386|x86_64)_get_synthetic_symtab|bfd_get_section_by_name|memcmp|bfd_malloc|@plt|\.plt`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d8538 .plt; 1d8542 .plt.got; 1be550 .plt`。随后 objdump+rg 用模式 `1fe2d7|1fe2dc|1fe2e5|1fe2ee|1fe2fb|1d8538|1d8542; 1ff317|1ff31c|1ff325|1ff32e|1ff33b|1d9538|1d9542` 将锚点关联到地址簇 0x2111, 0x1d8538, 0x2125, 0x1d9538。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0xe5600-0xe6100, binutils-2.29.1-o0-objdump:0xe5800-0xe6400, binutils-2.30-o0-objdump:0xe7800-0xe8600, binutils-2.31-o0-objdump:0xd6e00-0xd7c50, binutils-2.30-o0-objdump:0xe7a90-0xe7e40。

Windows: `binutils-2.29-o0-objdump:0xe5600-0xe6100`; `binutils-2.29.1-o0-objdump:0xe5800-0xe6400`; `binutils-2.30-o0-objdump:0xe7800-0xe8600`; `binutils-2.31-o0-objdump:0xd6e00-0xd7c50`; `binutils-2.30-o0-objdump:0xe7a90-0xe7e40`; `binutils-2.30-o0-objdump:0xe7e20-0xe8120`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.29-o0-objdump binutils-2.29.1-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump | rg 'elf_(i386|x86_64)_...` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.29-o0-objdump | rg '\\.plt(\\.got|\\.sec|\\.bnd)?"'$|@plt$|'"\\.got\\.plt'"` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.29-o0-objdump | rg -n '1fe2d7|1fe2dc|1fe2e5|1fe2ee|1fe2fb|1d8538|1d8542'"`

## CVE-2017-14128

strings 找字符串锚点 `202858 Dwarf Error: Line info section is too small (%ld); 202890 Dwarf Error: Line info data is bigger (0x%lx) than the section (0x%lx); 205c80 Dwarf Error: Line info section is too small (%Ld)`。随后 objdump+rg 用模式 `203980|203948|2039e0; 205cb8|205c80|205d18` 将锚点关联到地址簇 0x221339, 0x203948, 0x20363c, 0x226524, 0x205c80, 0x2059dc。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x1393a0-0x139460, binutils-2.31-o0-objdump:0x1311e0-0x131275, binutils-2.30-o0-objdump:0x140d10-0x140da5, binutils-2.29.1-o0-objdump:0x139aa0-0x139b50。

Windows: `binutils-2.29-o0-objdump:0x1393a0-0x139460`; `binutils-2.31-o0-objdump:0x1311e0-0x131275`; `binutils-2.30-o0-objdump:0x140d10-0x140da5`; `binutils-2.29.1-o0-objdump:0x139aa0-0x139b50`

Trace: strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.29-o0-objdump | rg \"Line info data is bigger|space remaining in the section|than the section|Line info section...` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.29.1-o0-objdump | rg -n "203980|203948|2039e0" -C 6'`

## CVE-2017-14129

readelf/nm 先查符号或导入模式 `read_section|strstr|memcpy|malloc|free|_bfd_error_handler|bfd_get_section_contents|bfd_simple_get_relocated...; read_section|strstr|memcpy|malloc|free|_bfd_error_handler|bfd_get_section_contents|bfd_simple_get_relocated...`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d7ab6   -C, --demangle[=STYLE]         Decode mangled/processed symbol names; 1de820 Compilation unit count must be >= 1 in .debug_names; 1d8ab6   -C, --demangle[=STYLE]         Decode mangled/processed symbol names`。随后 objdump+rg 用模式 `2059b8|2059e0|_str|names|not NUL; Dwarf Error|not NUL|_str|names|1e80|1e81|205c` 将锚点关联到地址簇 0x2, 0x311fd0, 0x311c28, 0x175349, 0x2f5090, 0x191675。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x13dc80-0x13de80, binutils-2.29-o0-objdump:0x136330-0x136520。

Windows: `binutils-2.30-o0-objdump:0x13dc80-0x13de80`; `binutils-2.29-o0-objdump:0x136330-0x136520`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -sW binutils-2.29-o0-objdump | rg 'read_section|strstr|memcpy|malloc|free|_bfd_error_handler|bfd_get_section_contents|bfd_simple_g...` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.29-o0-objdump | rg 'warning: dwarf string section|Dwarf Error: Offset|_str"'$|names$|Dwarf Error: Can'"'"` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.30-o0-objdump | rg -n '2059b8|2059e0|_str|names|not NUL' -C 20"`

## CVE-2017-14130

readelf/nm 先查符号或导入模式 `bfd_malloc|bfd_get_section_contents|_bfd_elf_parse_attributes|malloc|free|strlen|strdup; malloc|free|strlen|strdup|memcpy|strcmp|puts|printf`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1016 dlerror; 1203 ferror; 1d83a8   -e, --debugging-tags     Display debug information using ctags style`。随后 objdump+rg 用模式 `malloc|free|strlen|strdup|memcpy|strcmp|sprintf|snprintf|<|"; 201990|_bfd_elf_parse_attributes|2012e7|\.gnu\.attributes|201880|vendor-specific|2018e8|Object tag` 将锚点关联到地址簇 0x7, 0x8, 0x9, 0x125441, 0x2012e7, 0x12cb9f。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x12c000-0x12d100, binutils-2.29.1-o0-objdump:0x12c600-0x12d800, binutils-2.29-o0-objdump:0x12c750-0x12cc40, binutils-2.29.1-o0-objdump:0x12cd30-0x12d230, binutils-2.30-o0-objdump:0x133f00-0x134500。

Windows: `binutils-2.29-o0-objdump:0x12c000-0x12d100`; `binutils-2.29.1-o0-objdump:0x12c600-0x12d800`; `binutils-2.29-o0-objdump:0x12c750-0x12cc40`; `binutils-2.29.1-o0-objdump:0x12cd30-0x12d230`; `binutils-2.30-o0-objdump:0x133f00-0x134500`; `binutils-2.31-o0-objdump:0x124400-0x124a50`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.29-o0-objdump | rg 'bfd_malloc|bfd_get_section_contents|_bfd_elf_parse_attributes|malloc|free|strlen|strdup'"` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.29-o0-objdump | rg -i 'attribute|Tag_|aeabi|gnu|ARCH|proc|error|bfd_get_section_contents'"` | xref cmd: `/bin/zsh -lc "objdump -d -j .plt.sec binutils-2.29-o0-objdump | rg -n 'malloc|free|strlen|strdup|memcpy|strcmp|sprintf|snprintf|<|"'^ '"'"`

## CVE-2017-14529

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1ead18 	DLL Name: %.*s; 1ead30 	vma:  Hint/Ord Member-Name Bound-To; 2071b0 	DLL Name: %.*s`。随后 objdump+rg 用模式 `2090e8|209170|20c688|20c718; 206058|2060e0|2094f8|209588` 将锚点关联到地址簇 0x16f0cf, 0x16f0d3, 0x16f0da, 0x16cfc5, 0x16cfc9, 0x16cfd0。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x16d260-0x16d340, binutils-2.30-o0-objdump:0x16f370-0x16f450。

Windows: `binutils-2.29-o0-objdump:0x16d260-0x16d340`; `binutils-2.30-o0-objdump:0x16f370-0x16f450`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.29-o0-objdump binutils-2.29.1-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump'` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.31-o0-objdump | rg \"Hint/Ord|<corrupt: 0x%04lx>|DLL Name|first thunk|%04lx\\t %4d|%lx%08lx|HintName\""` | xref cmd: `/bin/zsh -lc 'objdump -drwC --section=.text binutils-2.30-o0-objdump | rg -C 4 "2090e8|209170|20c688|20c718"'`

## CVE-2017-14729

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；strings 找字符串锚点 `1f9709 The following i386/x86-64 specific disassembler options are supported for use; 1f97a8   x86-64      Disassemble in 64bit mode; 1c0cbd (Borland fastcall i386)`。随后 objdump+rg 用模式 `1e422c|1e60fc; 1fe2fb|1fea71|203cb0|20040c` 将锚点关联到地址簇 0xdd5d9, 0xdd5e0, 0xdd5e3, 0xe6900, 0xe6907, 0xe690a。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0xe6100-0xe6a20, binutils-2.30-o0-objdump:0xed500-0xedc80, binutils-2.31-o0-objdump:0xdd000-0xdd680, binutils-2.31.1-o0-objdump:0xdd000-0xdd680, binutils-2.29-o0-objdump:0x14c800-0x14d120。

Windows: `binutils-2.29-o0-objdump:0xe6100-0xe6a20`; `binutils-2.30-o0-objdump:0xed500-0xedc80`; `binutils-2.31-o0-objdump:0xdd000-0xdd680`; `binutils-2.31.1-o0-objdump:0xdd000-0xdd680`; `binutils-2.29-o0-objdump:0x14c800-0x14d120`; `binutils-2.30-o0-objdump:0x110400-0x110c30`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -sW binutils-2.30-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.29-o0-objdump | rg '@plt|\\+0x|JUMP_SLOT|GLOB_DAT|IRELATIVE|x86-64|i386'"` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.31-o0-objdump | rg -C 8 '1e422c|1e60fc'"`

## CVE-2017-14745

readelf/nm 先查符号或导入模式 `bfd_canonicalize_dynamic_reloc|qsort|_bfd_x86_elf_get_synthetic_symtab|compare_relocs; bfd_canonicalize_dynamic_reloc|qsort|_bfd_x86_elf_get_synthetic_symtab|compare_relocs`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d8538 .plt; 1d8542 .plt.got; 1da550 .plt`。随后 objdump+rg 用模式 `<qsort@plt>|call.*qsort; 1fe2fb|1fea71|20040c|203cb0` 将锚点关联到地址簇 0x558, 0x5683, 0x6204, 0xe692c, 0x1fe2fb, 0xe907a。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0xe5800-0xe5b50, binutils-2.30-o0-objdump:0xed400-0xed650, binutils-2.31-o0-objdump:0xdce00-0xdd080, binutils-2.31.1-o0-objdump:0xdce00-0xdd080, binutils-2.29-o0-objdump:0xe8f00-0xe9250。

Windows: `binutils-2.29-o0-objdump:0xe5800-0xe5b50`; `binutils-2.30-o0-objdump:0xed400-0xed650`; `binutils-2.31-o0-objdump:0xdce00-0xdd080`; `binutils-2.31.1-o0-objdump:0xdce00-0xdd080`; `binutils-2.29-o0-objdump:0xe8f00-0xe9250`; `binutils-2.29-o0-objdump:0x109850-0x109ba0`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.30-o0-objdump | rg 'bfd_canonicalize_dynamic_reloc|qsort|_bfd_x86_elf_get_synthetic_symtab|compare_relocs'"` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.29-o0-objdump | rg '@plt|\\+0x|@got|%s@plt|\\.plt'"` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.30-o0-objdump | rg -n '<qsort@plt>|call.*qsort'"`

## CVE-2017-14930

readelf/nm 先查符号或导入模式 `decode_line_info| sort_line_sequences| free@| free"; decode_line_info| sort_line_sequences| free@| free"`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d7452   --dwarf[=rawline,=decodedline,=info,=abbrev,=pubnames,=aranges,=macro,=frames,; 1d7533                            Display DWARF info in the file; 1bd45a   --dwarf[=rawline,=decodedline,=info,=abbrev,=pubnames,=aranges,=macro,=frames,`。随后 objdump+rg 用模式 `<(free|bfd_alloc|bfd_realloc|malloc|calloc)@plt>|"` 做候选代码块定位。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x202000-0x203000, binutils-2.29-o0-objdump:0x137f00-0x13b600, binutils-2.30-o0-objdump:0x13f800-0x142600, binutils-2.31.1-o0-objdump:0x12fd00-0x132b00, binutils-2.31-o0-objdump:0x12fd00-0x132b00。

Windows: `binutils-2.29-o0-objdump:0x202000-0x203000`; `binutils-2.29-o0-objdump:0x137f00-0x13b600`; `binutils-2.30-o0-objdump:0x13f800-0x142600`; `binutils-2.31.1-o0-objdump:0x12fd00-0x132b00`; `binutils-2.31-o0-objdump:0x12fd00-0x132b00`; `binutils-2.30-o0-objdump:0x1425f6-0x142720`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -sW binutils-2.29-o0-objdump | rg 'decode_line_info| sort_line_sequences| free@| free"'$'"'"` | strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.29-o0-objdump | rg -i 'debug_line|line info|line number|dwarf|sequence|sequences|read.*line|line.*data'"` | xref cmd: `/bin/zsh -lc "objdump -d -j .plt binutils-2.29-o0-objdump | rg '<(free|bfd_alloc|bfd_realloc|malloc|calloc)@plt>|"'^[[:space:]]*[0-9a-f]+ <'"'"`

## CVE-2017-14932

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `202748 Dwarf Error: mangled line number section (bad file number).; 202890 Dwarf Error: Line info data is bigger (0x%lx) than the section (0x%lx); 205b88 Dwarf Error: mangled line number section (bad file number).`。随后 objdump+rg 用模式 `205cb8|205d48|205df8|205e28|205b88; 202890|202908|2029b8|2029e8|202748` 将锚点关联到地址簇 0x13fac4, 0x13fac7, 0x13fac9, 0x138180, 0x138183, 0x138185。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x139850-0x13a700, binutils-2.30-o0-objdump:0x1411c0-0x141f50, binutils-2.29-o0-objdump:0x13a6c0-0x13a830, binutils-2.30-o0-objdump:0x141ef0-0x142050, binutils-2.31-o0-objdump:0x131f00-0x132110。

Windows: `binutils-2.29-o0-objdump:0x139850-0x13a700`; `binutils-2.30-o0-objdump:0x1411c0-0x141f50`; `binutils-2.29-o0-objdump:0x13a6c0-0x13a830`; `binutils-2.30-o0-objdump:0x141ef0-0x142050`; `binutils-2.31-o0-objdump:0x131f00-0x132110`; `binutils-2.31-o0-objdump:0x131480-0x131590`

Trace: strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.29-o0-objdump | rg 'Dwarf Error: (Line info data|Ran out of room reading|mangled line number section)'"` | xref cmd: `/bin/zsh -lc "objdump -d --no-show-raw-insn --section=.text binutils-2.30-o0-objdump | rg -C 5 '205cb8|205d48|205df8|205e28|205b88'"`

## CVE-2017-14933

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `202578 Dwarf Error: Can't find %s section.; 2025a0 Dwarf Error: Offset (%lu) greater than or equal to %s size (%lu).; 1d7038  Display information from object <file(s)>.`。随后 objdump+rg 用模式 `202578|202648|202688|202748|2027a0|202858|2029e8; 1e8ba0|1e8bc0|1e8bf8|1e8cd8` 将锚点关联到地址簇 0x213052, 0x202578, 0x20259c, 0x206634, 0x1e8ba0, 0x1e899c。据此把后续反汇编收敛到窗口 binutils-2.31.1-o0-objdump:0x130b40-0x130f50, binutils-2.30-o0-objdump:0x140650-0x140a80, binutils-2.31-o0-objdump:0x130b40-0x130f50, binutils-2.29-o0-objdump:0x138d80-0x1390d0, binutils-2.31.1-o0-objdump:0x12f267-0x12fbb0。

Windows: `binutils-2.31.1-o0-objdump:0x130b40-0x130f50`; `binutils-2.30-o0-objdump:0x140650-0x140a80`; `binutils-2.31-o0-objdump:0x130b40-0x130f50`; `binutils-2.29-o0-objdump:0x138d80-0x1390d0`; `binutils-2.31.1-o0-objdump:0x12f267-0x12fbb0`; `binutils-2.31-o0-objdump:0x12f267-0x12fbb0`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.29-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc "for f in binutils-2.29-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump; do printf '%s\\n' \""'$f";...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel --no-show-raw-insn binutils-2.29-o0-objdump | rg -n '202578|202648|202688|202748|2027a0|202858|2029e8' -C 8"`

## CVE-2017-14934

readelf/nm 先查符号或导入模式 `FUNC|sprintf|printf|warn|error|strlen|dwarf|process_debug_info`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1db0a8   Compilation Unit @ offset 0x%s:; 1db0d9    Length:        0x%s (%s); 1dd570   Compilation Unit @ offset 0x%s:`。随后 objdump+rg 用模式 `1dd570|1dd5a1|1dd710|1dd750|1dd798|1dd7d8|1dd830|1dd450|1dd488; 1db0a8|1db0d9|1db248|1db2a8|1db2e8|1db330|1db370|1db3c8|1daf68|1dafa0` 将锚点关联到地址簇 0x17734, 0x1dd450, 0x17761, 0x16704, 0x1daf68, 0x16731。据此把后续反汇编收敛到窗口 binutils-2.31.1-o0-objdump:0x71f00-0x72790, binutils-2.31-o0-objdump:0x71f00-0x72790, binutils-2.29-o0-objdump:0x6f800-0x70430, binutils-2.30-o0-objdump:0x72d00-0x73570。

Windows: `binutils-2.31.1-o0-objdump:0x71f00-0x72790`; `binutils-2.31-o0-objdump:0x71f00-0x72790`; `binutils-2.29-o0-objdump:0x6f800-0x70430`; `binutils-2.30-o0-objdump:0x72d00-0x73570`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.29-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump | rg 'FUNC|sprintf|print...` | strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.29-o0-objdump | rg 'length of CU at %s is negative|extends beyond end of section|Compilation Unit @ offset|Lengt...` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.30-o0-objdump | rg -n '1dd570|1dd5a1|1dd710|1dd750|1dd798|1dd7d8|1dd830|1dd450|1dd488'"`

## CVE-2017-14938

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1ff8b6 .gnu.version_d; 1ff8c5 .gnu.version_r; 202c5e .gnu.version_d`。随后 objdump+rg 用模式 `1fff90|1fffb8; 1e5c30|1e5c58` 将锚点关联到地址簇 0x103228, 0x10322a, 0x10322b, 0xfa013, 0xfa015, 0xfa016。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x102f00-0x103420, binutils-2.30-o0-objdump:0x109fb0-0x10a390, binutils-2.31.1-o0-objdump:0xf9eb0-0xfa290, binutils-2.31-o0-objdump:0xf9eb0-0xfa290, binutils-2.29-o0-objdump:0xcd430-0xcd560。

Windows: `binutils-2.29-o0-objdump:0x102f00-0x103420`; `binutils-2.30-o0-objdump:0x109fb0-0x10a390`; `binutils-2.31.1-o0-objdump:0xf9eb0-0xfa290`; `binutils-2.31-o0-objdump:0xf9eb0-0xfa290`; `binutils-2.29-o0-objdump:0xcd430-0xcd560`; `binutils-2.31.1-o0-objdump:0xc2f30-0xc3030`

Trace: strings cmd: `/bin/zsh -lc "strings -tx binutils-2.29-o0-objdump | rg \"gnu\\.version_[rd] invalid entry|verneed|verdef|version_r|version_d\""` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.29-o0-objdump | rg "1fff90|1fffb8" -C 6'`

## CVE-2017-14939

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1df208 Row index (%u) * num columns (%u) > space remaining in section; 202858 Dwarf Error: Line info section is too small (%ld); 1e1838 Row index (%u) * num columns (%u) > space remaining in section`。随后 objdump+rg 用模式 `1e8c78|line info data|Line info data; 202890|2028d8|Line info data` 将锚点关联到地址簇 0x211535, 0x1e8c78, 0x220999, 0x202890, 0x221033, 0x226610。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x139340-0x1394d0, binutils-2.30-o0-objdump:0x140c90-0x140e30, binutils-2.31.1-o0-objdump:0x131160-0x131290, binutils-2.31-o0-objdump:0x131160-0x131290。

Windows: `binutils-2.29-o0-objdump:0x139340-0x1394d0`; `binutils-2.30-o0-objdump:0x140c90-0x140e30`; `binutils-2.31.1-o0-objdump:0x131160-0x131290`; `binutils-2.31-o0-objdump:0x131160-0x131290`

Trace: strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.29-o0-objdump | rg 'Line info data is bigger|space remaining|Line info section is too small|Unhandled \\.debug_...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.31.1-o0-objdump | rg -n '1e8c78|line info data|Line info data'"`

## CVE-2017-14940

strings 找字符串锚点 `12d0 __errno_location; 1d7364   -g, --debugging          Display debug information in object file; 12d3 __errno_location`。随后 objdump+rg 将锚点关联到地址簇 0x129157, 0x129248, 0x129450, 0x104972, 0x105012, 0x108522。没有显式 start/stop 局部窗口；定位结果主要是 objdump+rg 的上下文地址簇。

Trace: strings cmd: `/bin/zsh -lc 'strings -a -t x binutils-2.29-o0-objdump | rg -i "debug_info|DW_AT|DW_OP|corrupt|abstract|location|debug"'` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.31.1-o0-objdump | rg -n -C 8 \"cmp\\s+al,0x3"'$|cmp'"\\s+eax,0x3"'$|cmp'"\\s+rax,0x3"'$"'`

## CVE-2017-14974

readelf/nm 先查符号或导入模式 `bfd_canonicalize_dynamic_reloc|qsort|synthetic|elf_i386|elf_x86_64; bfd_canonicalize_dynamic_reloc|qsort|synthetic|elf_i386|elf_x86_64`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `canonicalize_dynamic_reloc|get_synthetic_symtab|synthetic|dynamic reloc|dynrel|qsort`。随后 objdump+rg 用模式 `qsort@plt|call.*<qsort; qsort@plt|call.*<qsort` 将锚点关联到地址簇 0x2f2cc0, 0x554, 0x2f2cc8, 0x30bcc0, 0x30bcc8, 0x311ca0。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x165c80-0x165e70, binutils-2.29-o0-objdump:0x168050-0x168250, binutils-2.29-o0-objdump:0x185010-0x185210, binutils-2.29-o0-objdump:0x18cbb0-0x18cdb0, binutils-2.29-o0-objdump:0xf94e0-0xf9760。

Windows: `binutils-2.29-o0-objdump:0x165c80-0x165e70`; `binutils-2.29-o0-objdump:0x168050-0x168250`; `binutils-2.29-o0-objdump:0x185010-0x185210`; `binutils-2.29-o0-objdump:0x18cbb0-0x18cdb0`; `binutils-2.29-o0-objdump:0xf94e0-0xf9760`; `binutils-2.29-o0-objdump:0xfb1c0-0xfb450`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.29-o0-objdump | rg 'bfd_canonicalize_dynamic_reloc|qsort|synthetic|elf_i386|elf_x86_64'"` | strings cmd: `/bin/zsh -lc "strings -a binutils-2.29-o0-objdump | rg 'canonicalize_dynamic_reloc|get_synthetic_symtab|synthetic|dynamic reloc|dynrel|qsort'"` | xref cmd: `/bin/zsh -lc "objdump -d binutils-2.31.1-o0-objdump | rg -n -C 3 'qsort@plt|call.*<qsort'"`

## CVE-2017-15020

readelf/nm 先查符号或导入模式 `"`。随后 objdump+rg 用模式 `call.*<strnlen@plt>; call.*<strnlen@plt>` 将锚点关联到地址簇 0x101561, 0x101679, 0x1e7c38, 0x207299, 0x201820, 0x263072。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x13cea0-0x13d5d0, binutils-2.29-o0-objdump:0x12c720-0x12cc40, binutils-2.31-o0-objdump:0x12d300-0x12d5d0, binutils-2.31.1-o0-objdump:0x12d300-0x12d5d0, binutils-2.30-o0-objdump:0x13cddd-0x13cef8。

Windows: `binutils-2.30-o0-objdump:0x13cea0-0x13d5d0`; `binutils-2.29-o0-objdump:0x12c720-0x12cc40`; `binutils-2.31-o0-objdump:0x12d300-0x12d5d0`; `binutils-2.31.1-o0-objdump:0x12d300-0x12d5d0`; `binutils-2.30-o0-objdump:0x13cddd-0x13cef8`; `binutils-2.31-o0-objdump:0x12d260-0x12d398`

Trace: symbol/import cmd: `/bin/zsh -lc 'for f in binutils-2.29-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump; do if [ -e "$f" ]; then pr...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.31.1-o0-objdump | rg -n -C 24 'call.*<strnlen@plt>'"`

## CVE-2017-15021

readelf/nm 先查符号或导入模式 `bfd_get_debug_link_info|bfd_malloc_and_get_section|strnlen|bfd_get_section_by_name|bfd_getl32|bfd_get_32; bfd_get_debug_link_info|bfd_malloc_and_get_section|strnlen|bfd_get_section_by_name|bfd_getl32|bfd_get_32`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1fb6b7 .gnu_debuglink; 1c50f0 The debuglink filename is corrupt/missing; 1c5140 .gnu_debuglink`。随后 objdump+rg 用模式 `1e14d8|1c5140|\.gnu_debuglink|strnlen@plt; 1e1837|1c5180|\.gnu_debuglink|strnlen@plt` 将锚点关联到地址簇 0x689, 0x10552, 0x10929, 0x698, 0x10488, 0x10865。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0xcd600-0xcd900, binutils-2.31.1-o0-objdump:0xc31d0-0xc34f0, binutils-2.30-o0-objdump:0xd3d40-0xd4020, binutils-2.31-o0-objdump:0xc31d0-0xc34f0。

Windows: `binutils-2.29-o0-objdump:0xcd600-0xcd900`; `binutils-2.31.1-o0-objdump:0xc31d0-0xc34f0`; `binutils-2.30-o0-objdump:0xd3d40-0xd4020`; `binutils-2.31-o0-objdump:0xc31d0-0xc34f0`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -sW binutils-2.29-o0-objdump | rg 'bfd_get_debug_link_info|bfd_malloc_and_get_section|strnlen|bfd_get_section_by_name|bfd_getl32|b...` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.29-o0-objdump | rg '\\.gnu_debuglink|debuglink'"` | xref cmd: `/bin/zsh -lc "objdump -d --no-show-raw-insn binutils-2.31-o0-objdump | rg -n '1e14d8|1c5140|\\.gnu_debuglink|strnlen@plt'"`

## CVE-2017-15022

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d9570 DW_FORM_strp offset too big: %s; 1d95f0 DW_FORM_line_strp offset too big: %s; 1db5e8 DW_FORM_strp offset too big: %s`。随后 objdump+rg 用模式 `1e9120|DW_AT_comp_dir|1e; 202cc0|202b90|202bf8|202c58` 将锚点关联到地址簇 0xddd1e, 0xddd34, 0x1e4830, 0x13c291, 0x202b90, 0x13c3f3。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x13be00-0x13c900, binutils-2.30-o0-objdump:0x143800-0x144300, binutils-2.31-o0-objdump:0x133e00-0x134850, binutils-2.31.1-o0-objdump:0x133400-0x133f00, binutils-2.31.1-o0-objdump:0x133e00-0x134850。

Windows: `binutils-2.29-o0-objdump:0x13be00-0x13c900`; `binutils-2.30-o0-objdump:0x143800-0x144300`; `binutils-2.31-o0-objdump:0x133e00-0x134850`; `binutils-2.31.1-o0-objdump:0x133400-0x133f00`; `binutils-2.31.1-o0-objdump:0x133e00-0x134850`; `binutils-2.31-o0-objdump:0x133400-0x133f00`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.30-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.29-o0-objdump | rg 'DW_AT_comp_dir|non-string|Dwarf Error|DW_AT_name|DW_FORM'"` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.31.1-o0-objdump | rg '1e9120|DW_AT_comp_dir|1e'"`

## CVE-2017-15023

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1db728 	(Unknown format content type %s); 2027a0 Dwarf Error: Unknown format content type %lu.`。随后 objdump+rg 用模式 `1e83e8|1e8408|Unknown format content type|1e8428; 1e8ba0|1e8bc0|1e8be0` 将锚点关联到地址簇 0x211175, 0x1e83e8, 0x1e821c, 0x1e8ba0, 0x1e899c, 0x220678。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x140640-0x1407d0, binutils-2.29-o0-objdump:0x138c00-0x138db0, binutils-2.31.1-o0-objdump:0x130b10-0x130c80, binutils-2.31-o0-objdump:0x130b10-0x130c80, binutils-2.29-o0-objdump:0x138d70-0x139020。

Windows: `binutils-2.30-o0-objdump:0x140640-0x1407d0`; `binutils-2.29-o0-objdump:0x138c00-0x138db0`; `binutils-2.31.1-o0-objdump:0x130b10-0x130c80`; `binutils-2.31-o0-objdump:0x130b10-0x130c80`; `binutils-2.29-o0-objdump:0x138d70-0x139020`

Trace: strings cmd: `/bin/zsh -lc "for b in binutils-2.29-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump; do printf '%s\\n' \""'$b";...` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.31-o0-objdump | rg -n '1e83e8|1e8408|Unknown format content type|1e8428' -C 8"`

## CVE-2017-15024

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `202a40 Dwarf Error: Unable to read alt ref %u.; 202a68 Dwarf Error: Could not find abbrev number %u.; 205eb0 Dwarf Error: Unable to read alt ref %llu.`。随后 objdump+rg 用模式 `202a40|202a68; 1e8680|1e86b0|1e86d8|1e8708` 将锚点关联到地址簇 0x13b414, 0x13b418, 0x13b41c, 0x13308d, 0x133091, 0x133095。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x13b280-0x13b6d0, binutils-2.29-o0-objdump:0x13b6d0-0x13b940, binutils-2.30-o0-objdump:0x142bd0-0x143140, binutils-2.31-o0-objdump:0x133000-0x133650, binutils-2.31.1-o0-objdump:0x133000-0x133650。

Windows: `binutils-2.29-o0-objdump:0x13b280-0x13b6d0`; `binutils-2.29-o0-objdump:0x13b6d0-0x13b940`; `binutils-2.30-o0-objdump:0x142bd0-0x143140`; `binutils-2.31-o0-objdump:0x133000-0x133650`; `binutils-2.31.1-o0-objdump:0x133000-0x133650`

Trace: strings cmd: `/bin/zsh -lc "for f in binutils-2.29-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump; do printf '%s\\n' \""'$f";...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.29-o0-objdump | rg '202a40|202a68' -C 8"`

## CVE-2017-15025

readelf/nm 先查符号或导入模式 `decode_line_info|bfd|sprintf|strlen|_bfd_safe_read_leb128|bfd_set_error|error_handler; decode_line_info|bfd|sprintf|strlen|_bfd_safe_read_leb128|bfd_set_error|error_handler`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `202748 Dwarf Error: mangled line number section (bad file number).; 202890 Dwarf Error: Line info data is bigger (0x%lx) than the section (0x%lx); 205b88 Dwarf Error: mangled line number section (bad file number).`。未看到明确 objdump+rg 粗定位，模型直接进入局部窗口或停在符号/字符串级定位。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x5e740-0x5ee10, binutils-2.31.1-o0-objdump:0x5f740-0x5fe10, binutils-2.29-o0-objdump:0x139880-0x13a480, binutils-2.30-o0-objdump:0x1411c0-0x141c80, binutils-2.29-o0-objdump:0x13a3b0-0x13a520。

Windows: `binutils-2.29-o0-objdump:0x5e740-0x5ee10`; `binutils-2.31.1-o0-objdump:0x5f740-0x5fe10`; `binutils-2.29-o0-objdump:0x139880-0x13a480`; `binutils-2.30-o0-objdump:0x1411c0-0x141c80`; `binutils-2.29-o0-objdump:0x13a3b0-0x13a520`; `binutils-2.30-o0-objdump:0x141bd0-0x141d50`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.31.1-o0-objdump | rg 'decode_line_info|bfd|sprintf|strlen|_bfd_safe_read_leb128|bfd_set_error|error_handler'"` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.29-o0-objdump | rg 'Dwarf Error: (Invalid maximum operations|Ran out of room reading opcodes|mangled line numbe...`

## CVE-2017-15225

readelf/nm 先查符号或导入模式 ` UND .*free| UND .*malloc| UND .*calloc| UND .*realloc; free|malloc|calloc|realloc|close`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1de9c0 name_count == buckets_filled + hash_clash_count; 1fb360 /home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/bfd/hash.c; 1e0eb8 name_count == buckets_filled + hash_clash_count`。随后 objdump+rg 用模式 `<.*free|<[a-z_].*@plt>|Disassembly` 将锚点关联到地址簇 0x5, 0x13, 0x17。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x13eef9-0x13f276, binutils-2.30-o0-objdump:0x1468d9-0x146c93, binutils-2.31-o0-objdump:0x136e47-0x137201, binutils-2.31.1-o0-objdump:0x136e47-0x137201, binutils-2.30-o0-objdump:0xd06ff-0xd0780。

Windows: `binutils-2.29-o0-objdump:0x13eef9-0x13f276`; `binutils-2.30-o0-objdump:0x1468d9-0x146c93`; `binutils-2.31-o0-objdump:0x136e47-0x137201`; `binutils-2.31.1-o0-objdump:0x136e47-0x137201`; `binutils-2.30-o0-objdump:0xd06ff-0xd0780`; `binutils-2.31-o0-objdump:0xbf9bb-0xbfa3c`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.29-o0-objdump | rg ' UND .*free| UND .*malloc| UND .*calloc| UND .*realloc'"` | strings cmd: `/bin/zsh -lc "strings -a binutils-2.29-o0-objdump | rg -n 'dwarf|debug_info|debug_abbrev|debug_line|funcinfo|varinfo|hash' | head -100"` | xref cmd: `/bin/zsh -lc "objdump -d -j .plt binutils-2.29-o0-objdump | rg -n '<.*free|<[a-z_].*@plt>|Disassembly'"`

## CVE-2017-15938

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d7452   --dwarf[=rawline,=decodedline,=info,=abbrev,=pubnames,=aranges,=macro,=frames,; 1d74d9           =gdb_index,=trace_info,=trace_abbrev,=trace_aranges,`。随后 objdump+rg 用模式 `1e8e38|1e8e68|1e8e90|1e8ec0|205e91|2065e5; 202a40|202a68|202da0|202b90|202bf8|202c58|202cc0` 将锚点关联到地址簇 0x208789, 0x1e8e38, 0x1e899c, 0x218156, 0x202da0, 0x2025f8。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x13b2b0-0x13b490, binutils-2.30-o0-objdump:0x142b50-0x142e30, binutils-2.31-o0-objdump:0x133030-0x133330, binutils-2.31.1-o0-objdump:0x133030-0x133330。

Windows: `binutils-2.29-o0-objdump:0x13b2b0-0x13b490`; `binutils-2.30-o0-objdump:0x142b50-0x142e30`; `binutils-2.31-o0-objdump:0x133030-0x133330`; `binutils-2.31.1-o0-objdump:0x133030-0x133330`

Trace: strings cmd: `/bin/zsh -lc "strings -a binutils-2.29-o0-objdump | rg 'Dwarf Error: (Invalid abstract instance DIE ref|Abstract instance DIE ref zero|Unable to read al...` | xref cmd: `/bin/zsh -lc "objdump -d --no-show-raw-insn -M intel binutils-2.31.1-o0-objdump | rg -n '1e8e38|1e8e68|1e8e90|1e8ec0|205e91|2065e5' -C 8"`

## CVE-2017-15939

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1dbefc <unknown>; 1dbf41 CU: %s/%s:; 1dc768 <unknown>`。随后 objdump+rg 用模式 `<(strdup|strlen|sprintf|memset|realloc|malloc|free)@plt>; 202784|20278e|202797|5edb0|5ed60|5e8d0|5e9d0|5ec40` 将锚点关联到地址簇 0xce6dd, 0xce703, 0xce738, 0xd3c6c, 0xd424e, 0xd4313。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x138140-0x1383e0, binutils-2.30-o0-objdump:0x13fac0-0x13fd40, binutils-2.29-o0-objdump:0x1383d0-0x138760, binutils-2.30-o0-objdump:0x13fd30-0x1400d0, binutils-2.31.1-o0-objdump:0x1301f0-0x130590。

Windows: `binutils-2.29-o0-objdump:0x138140-0x1383e0`; `binutils-2.30-o0-objdump:0x13fac0-0x13fd40`; `binutils-2.29-o0-objdump:0x1383d0-0x138760`; `binutils-2.30-o0-objdump:0x13fd30-0x1400d0`; `binutils-2.31.1-o0-objdump:0x1301f0-0x130590`; `binutils-2.31-o0-objdump:0x1301f0-0x130590`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.29-o0-objdump'` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.29-o0-objdump | rg '<unknown>|%s/%s|Dwarf Error|mangled line|Line info data|Ran out of room reading'"` | xref cmd: `/bin/zsh -lc "objdump -d -j .plt.sec binutils-2.31-o0-objdump | rg '<(strdup|strlen|sprintf|memset|realloc|malloc|free)@plt>'"`

## CVE-2017-15996

readelf/nm 先查符号或导入模式 `strtoul|fread|malloc|fseek|printf|error; strtoul|fread|malloc|fseek|printf|error`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1e37f8 %s: invalid archive header size: %ld; 1e38d8 %s: the archive index is empty`。随后 objdump+rg 用模式 `<strtoul@plt>|call\s+.*<strtoul@plt>; call\s+64f00 <strtoul@plt>|<strtoul@plt>` 将锚点关联到地址簇 0x93065, 0x181069, 0x254431, 0x109428, 0x196265, 0x283251。没有显式 start/stop 局部窗口；定位结果主要是 objdump+rg 的上下文地址簇。

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.29-o0-objdump | rg 'strtoul|fread|malloc|fseek|printf|error'"` | strings cmd: `/bin/zsh -lc "for b in binutils-2.29-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump; do printf '%s\\n' \""'$b";...` | xref cmd: `/bin/zsh -lc "objdump -d binutils-2.31-o0-objdump | rg -n -B18 -A35 '<strtoul@plt>|call\\s+.*<strtoul@plt>'"`

## CVE-2017-16828

readelf/nm 先查符号或导入模式 `printf|putchar|warn|dwarf_vmatoa|strlen|sprintf; printf|putchar|warn|dwarf_vmatoa|strlen|sprintf`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `Augmentation data too long|Corrupt augmentation data length|Augmentation data:; Augmentation data too long|Corrupt augmentation data length|Augmentation data:`。随后 objdump+rg 用模式 `call\s+817ab|call\s+8169e; call\s+82500|call\s+823f3` 将锚点关联到地址簇 0x817f3, 0x820a0, 0x82f5c, 0x82548, 0x82df5, 0x83cb1。没有显式 start/stop 局部窗口；定位结果主要是 objdump+rg 的上下文地址簇。

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.29.1-o0-objdump | rg 'printf|putchar|warn|dwarf_vmatoa|strlen|sprintf'"` | strings cmd: `/bin/zsh -lc "strings -a binutils-2.30-o0-objdump | rg 'Augmentation data too long|Corrupt augmentation data length|Augmentation data:'"` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.31-o0-objdump | rg 'call\\s+817ab|call\\s+8169e'"`

## CVE-2017-16829

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；strings 找字符串锚点 `202b48 warning: %B: corrupt GNU_PROPERTY_TYPE (%ld) size: %#lx; 202b80 warning: %B: corrupt GNU_PROPERTY_TYPE (%ld) type (0x%x) datasz: 0x%x; 204ee8 warning: %B: corrupt GNU_PROPERTY_TYPE (%ld) size: %#lx`。随后 objdump+rg 用模式 `202b48|202b80|202bc8|202c28` 将锚点关联到地址簇 0x204775, 0x202b48, 0x202b43。据此把后续反汇编收敛到窗口 binutils-2.29.1-o0-objdump:0x12e600-0x12ea80, binutils-2.30-o0-objdump:0x135830-0x135cd0, binutils-2.31-o0-objdump:0x125d20-0x1261c0, binutils-2.31.1-o0-objdump:0x125d20-0x1261c0。

Windows: `binutils-2.29.1-o0-objdump:0x12e600-0x12ea80`; `binutils-2.30-o0-objdump:0x135830-0x135cd0`; `binutils-2.31-o0-objdump:0x125d20-0x1261c0`; `binutils-2.31.1-o0-objdump:0x125d20-0x1261c0`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.29.1-o0-objdump'` | strings cmd: `/bin/zsh -lc 'strings -a -tx binutils-2.29.1-o0-objdump | rg "GNU_PROPERTY_TYPE|corrupt stack size|unsupported GNU_PROPERTY"'` | xref cmd: `/bin/zsh -lc 'objdump -d --no-show-raw-insn binutils-2.29.1-o0-objdump | rg -n "202b48|202b80|202bc8|202c28" -C 8'`

## CVE-2017-16830

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `92e28 <corrupt GNU_PROPERTY_TYPE, size = %#lx>; 92e58 <corrupt type (%#x) datasz: %#x>; 9a4d0 <corrupt GNU_PROPERTY_TYPE, size = %#lx>`。随后 objdump+rg 用模式 `92e28|92e58|92f57|92e7a|92ebf; 9a4d0|9a4fa|9a518|9a53a|9a57f` 将锚点关联到地址簇 0x3ea88, 0x3ea8a, 0x3ea8e, 0x1d1b0, 0xb7714, 0x1d1b7。据此把后续反汇编收敛到窗口 binutils-2.29.1-o0-readelf:0x3ea40-0x3ef40, binutils-2.30-o0-readelf:0x401e0-0x406b0, binutils-2.31-o0-readelf:0x40c70-0x41150, binutils-2.31.1-o0-readelf:0x40c70-0x41150。

Windows: `binutils-2.29.1-o0-readelf:0x3ea40-0x3ef40`; `binutils-2.30-o0-readelf:0x401e0-0x406b0`; `binutils-2.31-o0-readelf:0x40c70-0x41150`; `binutils-2.31.1-o0-readelf:0x40c70-0x41150`

Trace: strings cmd: `/bin/zsh -lc "strings -tx binutils-2.29.1-o0-readelf | rg 'corrupt GNU_PROPERTY|corrupt descsz|corrupt type|x86 ISA used|stack size|unknown type|proceso...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.29.1-o0-readelf | rg -C 3 '92e28|92e58|92f57|92e7a|92ebf'"`

## CVE-2017-16831

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；strings 找字符串锚点 `1e453b Unrecognized XCOFF type %d; 1e6120 parse_coff_type: Bad type code 0x%x; 1e240b Unrecognized XCOFF type %d`。随后 objdump+rg 用模式 `208c78|20ab98|20abb8|1ec798|1ec7b8|1ed0f8|1ed118; 208c78|20ab98|20abb8|1ec798|1ec7b8|1ed0f8|1ed118` 将锚点关联到地址簇 0x262721, 0x1ec798, 0x262744, 0x268956, 0x208c78, 0x291530。据此把后续反汇编收敛到窗口 binutils-2.29.1-o0-objdump:0x180fe0-0x1811b0, binutils-2.30-o0-objdump:0x182730-0x182950, binutils-2.31-o0-objdump:0x165450-0x165640, binutils-2.31.1-o0-objdump:0x165450-0x165640, binutils-2.29.1-o0-objdump:0x1811d0-0x181310。

Windows: `binutils-2.29.1-o0-objdump:0x180fe0-0x1811b0`; `binutils-2.30-o0-objdump:0x182730-0x182950`; `binutils-2.31-o0-objdump:0x165450-0x165640`; `binutils-2.31.1-o0-objdump:0x165450-0x165640`; `binutils-2.29.1-o0-objdump:0x1811d0-0x181310`; `binutils-2.30-o0-objdump:0x182940-0x182a90`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.29.1-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc 'strings -a -t x binutils-2.30-o0-objdump | rg -i "corrupt symbol count|not enough memory to allocate space|symbols of size|Not enough memo...` | xref cmd: `/bin/zsh -lc 'objdump -d -Mintel binutils-2.31-o0-objdump | rg -n "208c78|20ab98|20abb8|1ec798|1ec7b8|1ed0f8|1ed118"'`

## CVE-2017-17080

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标。随后 objdump+rg 用模式 `1e6688|1e66[0-9a-f]|1e6524|1e6539; 2013c8|2013c[0-9a-f]|2012c8|2012dd` 将锚点关联到地址簇 0x6745, 0x6759, 0x7160, 0x169940, 0x2012c8, 0x169947。据此把后续反汇编收敛到窗口 binutils-2.29.1-o0-objdump:0x106e60-0x107090, binutils-2.30-o0-objdump:0x10dac0-0x10dc40, binutils-2.31-o0-objdump:0xfd9c0-0xfdb80, binutils-2.31.1-o0-objdump:0xfd9c0-0xfdb80, binutils-2.30-o0-objdump:0x10da90-0x10db95。

Windows: `binutils-2.29.1-o0-objdump:0x106e60-0x107090`; `binutils-2.30-o0-objdump:0x10dac0-0x10dc40`; `binutils-2.31-o0-objdump:0xfd9c0-0xfdb80`; `binutils-2.31.1-o0-objdump:0xfd9c0-0xfdb80`; `binutils-2.30-o0-objdump:0x10da90-0x10db95`; `binutils-2.31-o0-objdump:0xfd990-0xfdaa0`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.29.1-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.29.1-o0-objdump | rg -n \"netbsdcore\\.procinfo|openbsd|QNX|nto|\\.note\""` | xref cmd: `/bin/zsh -lc 'objdump -d -Mintel binutils-2.31.1-o0-objdump | rg -n "1e6688|1e66[0-9a-f]|1e6524|1e6539"'`

## CVE-2017-17122

readelf/nm 先查符号或导入模式 `"`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d9b30 RELOCATION RECORDS FOR [%s]:; 1d9b4d  (none)`。随后 objdump+rg 用模式 `1dab48|1dab65|1dab6e|1dab81; 1beb40|1beb5d|1beb66|1beb79` 将锚点关联到地址簇 0x6889b, 0x1dab48, 0x688b6, 0x679e9, 0x1beb40, 0x67a04。据此把后续反汇编收敛到窗口 binutils-2.31-o0-objdump:0x67990-0x67b50, binutils-2.30-o0-objdump:0x68840-0x68a00, binutils-2.29.1-o0-objdump:0x666f0-0x66890, binutils-2.31.1-o0-objdump:0x67990-0x67b50。

Windows: `binutils-2.31-o0-objdump:0x67990-0x67b50`; `binutils-2.30-o0-objdump:0x68840-0x68a00`; `binutils-2.29.1-o0-objdump:0x666f0-0x66890`; `binutils-2.31.1-o0-objdump:0x67990-0x67b50`

Trace: symbol/import cmd: `/bin/zsh -lc "for b in binutils-2.29.1-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump; do printf '%s\\n' \""'$b...` | strings cmd: `/bin/zsh -lc "for b in binutils-2.29.1-o0-objdump binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump; do printf '%s\\n' \""'$b...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.30-o0-objdump | rg '1dab48|1dab65|1dab6e|1dab81'"`

## CVE-2017-17124

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d9a57 no symbols; 1e4a30 %s: the archive has an index but no symbols; 1daa6f no symbols`。随后 objdump+rg 用模式 `1ec800|bad string|bfd_get_file_size|bfd_malloc|bfd_bread; 208cb0|bad string|bfd_get_file_size|bfd_malloc|bfd_bread` 将锚点关联到地址簇 0x165772, 0x1ec800, 0x181318, 0x208cb0, 0x182a8c, 0x20abfe。据此把后续反汇编收敛到窗口 binutils-2.29.1-o0-objdump:0x181220-0x1813f0, binutils-2.30-o0-objdump:0x182990-0x182b70, binutils-2.31-o0-objdump:0x165680-0x165850, binutils-2.31.1-o0-objdump:0x165680-0x165850。

Windows: `binutils-2.29.1-o0-objdump:0x181220-0x1813f0`; `binutils-2.30-o0-objdump:0x182990-0x182b70`; `binutils-2.31-o0-objdump:0x165680-0x165850`; `binutils-2.31.1-o0-objdump:0x165680-0x165850`

Trace: strings cmd: `/bin/zsh -lc 'strings -a -t x binutils-2.29.1-o0-objdump | rg "bad string table size|string table|no symbols|file truncated"'` | xref cmd: `/bin/zsh -lc 'objdump -d -Mintel binutils-2.31-o0-objdump | rg "1ec800|bad string|bfd_get_file_size|bfd_malloc|bfd_bread"'`

## CVE-2017-17126

readelf/nm 先查符号或导入模式 `get_data|sprintf|strlen|printf|bfd|malloc|free|strcmp|strncmp; get_data|sprintf|strlen|printf|bfd|malloc|free|strcmp|strncmp`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d81bb   -h, --[section-]headers  Display the contents of the section headers; 1d8241   -d, --disassemble        Display assembler contents of executable sections; 1d91bb   -h, --[section-]headers  Display the contents of the section headers`。随后 objdump+rg 用模式 `1da7de|1da7f8|1da81c|1dd510|1e1d94|1e1deb|1e2220; 1d97c6|1d97e0|1d9804|1dc046|1e04d4|1e052b` 将锚点关联到地址簇 0x7101, 0x1da7de, 0x7126, 0x7009, 0x1d97c6, 0x7034。据此把后续反汇编收敛到窗口 binutils-2.29.1-o0-objdump:0x64880-0x64e80, binutils-2.30-o0-objdump:0x669d0-0x66fd0, binutils-2.29.1-o0-objdump:0x64360-0x64830, binutils-2.30-o0-objdump:0x66380-0x66970, binutils-2.31-o0-objdump:0x653e0-0x66150。

Windows: `binutils-2.29.1-o0-objdump:0x64880-0x64e80`; `binutils-2.30-o0-objdump:0x669d0-0x66fd0`; `binutils-2.29.1-o0-objdump:0x64360-0x64830`; `binutils-2.30-o0-objdump:0x66380-0x66970`; `binutils-2.31-o0-objdump:0x653e0-0x66150`; `binutils-2.31.1-o0-objdump:0x653e0-0x66150`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -rW binutils-2.29.1-o0-objdump | rg "get_data|sprintf|strlen|printf|bfd|malloc|free|strcmp|strncmp"'` | strings cmd: `/bin/zsh -lc 'strings -tx binutils-2.29.1-o0-objdump | rg "string table|debug_(info|abbrev|line|str)|uncompressed|compressed|No comp|corrupt|section"'` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.30-o0-objdump | rg -n "1da7de|1da7f8|1da81c|1dd510|1e1d94|1e1deb|1e2220"'`

## CVE-2017-6965

readelf/nm 先查符号或导入模式 `( byte_put| error| warn| sprintf|strlen|puts|printf| UND )`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1ada1 MSP430x1H; 1add5 MSP430x1H; 1afd8 MSP430x1H`。随后 objdump+rg 用模式 `84c20|84c58|85720|85760|718|71a|71c|74f; 8f0d0|8f110|8f140|8f178|8f1b0|8f1f0|8f228|8f260|8f2a0|8f2d8|8fe08|8fe48` 将锚点关联到地址簇 0x67489, 0x67492, 0x68202, 0x39969, 0x8f0d0, 0x40010。据此把后续反汇编收敛到窗口 binutils-2.28-o0-readelf:0x31d80-0x320d0, binutils-2.30-o0-readelf:0x33380-0x33aa0, binutils-2.29-o0-readelf:0x32400-0x32b00, binutils-2.29.1-o0-readelf:0x32500-0x32c00, binutils-2.28-o0-readelf:0x31c80-0x31d20。

Windows: `binutils-2.28-o0-readelf:0x31d80-0x320d0`; `binutils-2.30-o0-readelf:0x33380-0x33aa0`; `binutils-2.29-o0-readelf:0x32400-0x32b00`; `binutils-2.29.1-o0-readelf:0x32500-0x32c00`; `binutils-2.28-o0-readelf:0x31c80-0x31d20`; `binutils-2.29.1-o0-readelf:0x324d0-0x32520`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.28-o0-readelf binutils-2.29-o0-readelf binutils-2.29.1-o0-readelf binutils-2.30-o0-readelf | rg -n "( byte_put| err...` | strings cmd: `/bin/zsh -lc 'strings -a -t x binutils-2.28-o0-readelf | rg "sym diff reloc writes past end|Unhandled MSP430|Unhandled MN10300|skipping invalid relocati...` | xref cmd: `/bin/zsh -lc 'objdump -d -Mintel binutils-2.28-o0-readelf | rg -n "84c20|84c58|85720|85760|718|71a|71c|74f"'`

## CVE-2017-6966

readelf/nm 确认动态符号/导入，如 `0000000a95f0  000000000008 R_X86_64_RELATIVE                    78a0; 0000000a95f8  000000000008 R_X86_64_RELATIVE                    7860`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `invalid symbol index|SYM_DIFF|sym diff reloc|Unhandled MSP430|Unhandled MN10300|RL78_SYM|MSP430 reloc|MN103...; invalid symbol index|SYM_DIFF|sym diff reloc|Unhandled MSP430|Unhandled MN10300|RL78_SYM|MSP430 reloc|MN103...`。随后 objdump+rg 用模式 ` error|warn|byte_put|free|malloc|calloc|sprintf|strlen; 84c20|84c58|71a6a|74fb7` 将锚点关联到地址簇 0xc85a, 0x71a41, 0xc861, 0x324d7, 0x324dd, 0x324e1。据此把后续反汇编收敛到窗口 binutils-2.29-o0-readelf:0x32320-0x32b20, binutils-2.28-o0-readelf:0x31c80-0x32100, binutils-2.29-o0-readelf:0x33f80-0x34470, binutils-2.29.1-o0-readelf:0x32540-0x32b00, binutils-2.29.1-o0-readelf:0x344f0-0x34560。

Windows: `binutils-2.29-o0-readelf:0x32320-0x32b20`; `binutils-2.28-o0-readelf:0x31c80-0x32100`; `binutils-2.29-o0-readelf:0x33f80-0x34470`; `binutils-2.29.1-o0-readelf:0x32540-0x32b00`; `binutils-2.29.1-o0-readelf:0x344f0-0x34560`; `binutils-2.30-o0-readelf:0x333d0-0x33ae0`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -r binutils-2.29-o0-readelf | head -80'` | strings cmd: `/bin/zsh -lc "strings -a binutils-2.28-o0-readelf | rg 'invalid symbol index|SYM_DIFF|sym diff reloc|Unhandled MSP430|Unhandled MN10300|RL78_SYM|MSP430 ...` | xref cmd: `/bin/zsh -lc "objdump -T binutils-2.29-o0-readelf | rg ' error|warn|byte_put|free|malloc|calloc|sprintf|strlen'"`

## CVE-2017-6969

readelf/nm 先查符号或导入模式 `"`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `8f140 MSP430 sym diff reloc contains invalid offset: 0x%lx; 8f228 MN10300 sym diff reloc contains invalid offset: 0x%lx`。随后 objdump+rg 用模式 `8f140|8f228|8f2d8|invalid offset|writes past; Unhandled MSP430|Unhandled MN10300|writes past|invalid offset|879` 将锚点关联到地址簇 0x32627, 0x32629, 0x3262b, 0x77b8, 0x406a9, 0x77bf。据此把后续反汇编收敛到窗口 binutils-2.29-o0-readelf:0x31d00-0x32b20, binutils-2.28-o0-readelf:0x5f500-0x62600, binutils-2.28-o0-readelf:0x30000-0x33000, binutils-2.28-o0-readelf:0x31b00-0x320d0, binutils-2.29.1-o0-readelf:0x325d0-0x32ad0。

Windows: `binutils-2.29-o0-readelf:0x31d00-0x32b20`; `binutils-2.28-o0-readelf:0x5f500-0x62600`; `binutils-2.28-o0-readelf:0x30000-0x33000`; `binutils-2.28-o0-readelf:0x31b00-0x320d0`; `binutils-2.29.1-o0-readelf:0x325d0-0x32ad0`; `binutils-2.30-o0-readelf:0x332f0-0x337f0`

Trace: symbol/import cmd: `/bin/zsh -lc "for f in binutils-2.28-o0-readelf binutils-2.29-o0-readelf binutils-2.29.1-o0-readelf binutils-2.30-o0-readelf; do printf '%s\\n' \""'$f";...` | strings cmd: `/bin/zsh -lc "for f in binutils-2.28-o0-readelf binutils-2.29-o0-readelf binutils-2.29.1-o0-readelf binutils-2.30-o0-readelf; do printf '%s\\n' \""'$f";...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.29-o0-readelf | rg '8f140|8f228|8f2d8|invalid offset|writes past' -C 5"`

## CVE-2017-7209

readelf/nm 先查符号或导入模式 `uncompress|inflate|error|warn|printf|sprintf|puts|strlen`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `Unable to decompress section|Hex dump of section|unsupported compress type|compressed section|ZLIB|has relo...`。随后 objdump+rg 用模式 `8ff68|8ff98|8ffbe|8ffc8|9008d|900a8|90130; 8ff58|8ff88|8ffae|8ffb8|9007d|90098|90120` 将锚点关联到地址簇 0x42232, 0x8ff68, 0x42251, 0x42301, 0x8ff58, 0x42320。据此把后续反汇编收敛到窗口 binutils-2.29-o0-readelf:0x349c0-0x350c0, binutils-2.28-o0-readelf:0x33e70-0x34520, binutils-2.29.1-o0-readelf:0x34af0-0x35220, binutils-2.30-o0-readelf:0x35e80-0x36610。

Windows: `binutils-2.29-o0-readelf:0x349c0-0x350c0`; `binutils-2.28-o0-readelf:0x33e70-0x34520`; `binutils-2.29.1-o0-readelf:0x34af0-0x35220`; `binutils-2.30-o0-readelf:0x35e80-0x36610`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.28-o0-readelf binutils-2.29-o0-readelf binutils-2.29.1-o0-readelf binutils-2.30-o0-readelf | rg -n "uncompress|infl...` | strings cmd: `/bin/zsh -lc "for f in binutils-2.28-o0-readelf binutils-2.29-o0-readelf binutils-2.29.1-o0-readelf binutils-2.30-o0-readelf; do printf '%s\\n' \""'$f";...` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.29-o0-readelf | rg -n -C 8 "8ff68|8ff98|8ffbe|8ffc8|9008d|900a8|90130"'`

## CVE-2017-7299

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1f032f ELFCLASS64; 1f033a ELFCLASS32; 202377 ELFCLASS64`。随后 objdump+rg 用模式 `201320|file class; 2023a0|file class` 将锚点关联到地址簇 0x201098, 0x201320, 0x201336, 0x2023a0, 0x206529, 0x204740。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0x119800-0x11c400, binutils-2.29-o0-objdump:0x124700-0x127300, binutils-2.29.1-o0-objdump:0x124b00-0x127700, binutils-2.30-o0-objdump:0x12bd00-0x12e900, binutils-2.28-o0-objdump:0x11a0d0-0x11ad80。

Windows: `binutils-2.28-o0-objdump:0x119800-0x11c400`; `binutils-2.29-o0-objdump:0x124700-0x127300`; `binutils-2.29.1-o0-objdump:0x124b00-0x127700`; `binutils-2.30-o0-objdump:0x12bd00-0x12e900`; `binutils-2.28-o0-objdump:0x11a0d0-0x11ad80`; `binutils-2.29.1-o0-objdump:0x125400-0x126100`

Trace: strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.28-o0-objdump | rg 'not in ELF format|file class|ELFCLASS'"` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.29-o0-objdump | rg -n '201320|file class'"`

## CVE-2017-7303

readelf/nm 先查符号或导入模式 `section_match|find_link|bfd_elf|sprintf|strlen; section_match|find_link|bfd_elf|sprintf|strlen`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `BFD|assert|Assertion|internal error|elf.c|section|shdr|PR 20922; BFD|assert|Assertion|internal error|elf.c|section|shdr|PR 20922`。随后 objdump+rg 用模式 `1ee178|1ee140|1edd00|1ea2d8; 1ff158|1ff120|1fece0|1faf6a` 将锚点关联到地址簇 0x2faa08, 0x98077, 0x1ea2d8, 0x30ebc8, 0x104690, 0x1faf6a。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0xe7900-0xe7aa0, binutils-2.29-o0-objdump:0xf1980-0xf1b20, binutils-2.29.1-o0-objdump:0xf1d40-0xf1ec0, binutils-2.30-o0-objdump:0xf8620-0xf87a0, binutils-2.28-o0-objdump:0xe7890-0xe7928。

Windows: `binutils-2.28-o0-objdump:0xe7900-0xe7aa0`; `binutils-2.29-o0-objdump:0xf1980-0xf1b20`; `binutils-2.29.1-o0-objdump:0xf1d40-0xf1ec0`; `binutils-2.30-o0-objdump:0xf8620-0xf87a0`; `binutils-2.28-o0-objdump:0xe7890-0xe7928`; `binutils-2.29-o0-objdump:0xf1930-0xf19bd`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.28-o0-objdump | rg "section_match|find_link|bfd_elf|sprintf|strlen"'` | strings cmd: `/bin/zsh -lc 'strings -a binutils-2.28-o0-objdump | rg -n "BFD|assert|Assertion|internal error|elf.c|section|shdr|PR 20922"'` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.28-o0-objdump | rg -n -C 6 "1ee178|1ee140|1edd00|1ea2d8"'`

## CVE-2017-7304

readelf/nm 先查符号或导入模式 `copy_special_section_fields|elf_numsections|_bfd_error_handler|find_link|sprintf|strlen`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1e9fa0 %B: Failed to find link section for section %d; 1e9fd0 %B: Failed to find info section for section %d`。随后 objdump+rg 用模式 `1ee140|1ee178|1ee1a8|ee140|ee178|ee1a8; 200188|2001c0|2001f0` 将锚点关联到地址簇 0x138600, 0x1ee140, 0x138636, 0x146748, 0x200188, 0x146784。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0xe7a70-0xe7be0, binutils-2.29-o0-objdump:0xf1b20-0xf1c90, binutils-2.29.1-o0-objdump:0xf1eb0-0xf2020, binutils-2.30-o0-objdump:0xf8790-0xf8a00。

Windows: `binutils-2.28-o0-objdump:0xe7a70-0xe7be0`; `binutils-2.29-o0-objdump:0xf1b20-0xf1c90`; `binutils-2.29.1-o0-objdump:0xf1eb0-0xf2020`; `binutils-2.30-o0-objdump:0xf8790-0xf8a00`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.28-o0-objdump | rg 'copy_special_section_fields|elf_numsections|_bfd_error_handler|find_link|sprintf|strlen'"` | strings cmd: `/bin/zsh -lc "for f in binutils-2.*-o0-objdump; do printf '%s\\n' \""'$f"; strings -a -t x "$f" | rg '"'Invalid sh_link|Failed to find link section|Fail...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel --no-show-raw-insn binutils-2.28-o0-objdump | rg -n '1ee140|1ee178|1ee1a8|ee140|ee178|ee1a8'"`

## CVE-2017-8392

readelf/nm 先查符号或导入模式 `__assert_fail|bfd_get_section|strlen|strcmp|fprintf`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `2036e8 /home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/bfd/dwarf2.c; 1f13f0 /home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/bfd/dwarf2.c; 205a38 /home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/bfd/dwarf2.c`。随后 objdump+rg 用模式 `# 2036e8|# 203d08|Dwarf Error|scan_unit_for_symbols|203668|203d08; # 205a38|# 206068|Dwarf Error|scan_unit_for_symbols|2059b8|206068` 将锚点关联到地址簇 0x203e90, 0x218863, 0x2036e8, 0x223329, 0x2059b8, 0x2059dc。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0x131400-0x131f50, binutils-2.29.1-o0-objdump:0x13e900-0x13f550, binutils-2.29-o0-objdump:0x13e200-0x13ee50, binutils-2.30-o0-objdump:0x145b00-0x146750, binutils-2.29-o0-objdump:0x13e3af-0x13e760。

Windows: `binutils-2.28-o0-objdump:0x131400-0x131f50`; `binutils-2.29.1-o0-objdump:0x13e900-0x13f550`; `binutils-2.29-o0-objdump:0x13e200-0x13ee50`; `binutils-2.30-o0-objdump:0x145b00-0x146750`; `binutils-2.29-o0-objdump:0x13e3af-0x13e760`; `binutils-2.28-o0-objdump:0x1315bc-0x131f80`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.28-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc 'strings -a -t x binutils-2.29.1-o0-objdump | rg "section == NULL|functionname_ptr|_bfd_dwarf2_find_nearest_line|dwarf2.c"'` | xref cmd: `/bin/zsh -lc 'objdump -d -Mintel binutils-2.29.1-o0-objdump | rg -n -C 8 "# 2036e8|# 203d08|Dwarf Error|scan_unit_for_symbols|203668|203d08"'`

## CVE-2017-8395

readelf/nm 先查符号或导入模式 ` malloc|free|zlib|compress|inflate|deflate|zError|compressBound|uncompress|zlibVersion; malloc|free|compress|inflate|deflate|zError|compressBound|uncompress|zlibVersion`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d5166 vcompressp%XW; 1d5174 vpcompress%LW; 1e5dca vcompressp%XW`。随后 objdump+rg 用模式 `<malloc@plt|<free@plt|<memcpy@plt|<memset@plt|<strlen@plt; 1ea528|1ea5c0|1ea640|1ee050|1ee088|5d5[0-9a-f]0 <|call.*5d|malloc` 将锚点关联到地址簇 0x60039, 0x6003f, 0x60040, 0x162895, 0x162912, 0x162928。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0xc7f00-0xc8d50, binutils-2.28-o0-objdump:0xc7f00-0xc8d50, binutils-2.30-o0-objdump:0xc7f00-0xc8d80, binutils-2.29.1-o0-objdump:0xc7f00-0xc8d80, binutils-2.28-o0-objdump:0xbe500-0xc0800。

Windows: `binutils-2.29-o0-objdump:0xc7f00-0xc8d50`; `binutils-2.28-o0-objdump:0xc7f00-0xc8d50`; `binutils-2.30-o0-objdump:0xc7f00-0xc8d80`; `binutils-2.29.1-o0-objdump:0xc7f00-0xc8d80`; `binutils-2.28-o0-objdump:0xbe500-0xc0800`; `binutils-2.29.1-o0-objdump:0xc8cec-0xc8ed0`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -s --dyn-syms binutils-2.28-o0-objdump | rg ' malloc|free|zlib|compress|inflate|deflate|zError|compressBound|uncompress|zlibVersion'"` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.28-o0-objdump | rg -i 'compress|zlib|debug.*compress|bfd.*compress|section.*compress'"` | xref cmd: `/bin/zsh -lc "objdump -d -j .plt binutils-2.30-o0-objdump | rg -A2 '<malloc@plt|<free@plt|<memcpy@plt|<memset@plt|<strlen@plt'"`

## CVE-2017-8396

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `reloc|out of range|howto|special|section|overflow; reloc|out of range|howto|special|section|overflow`。未看到明确 objdump+rg 粗定位，模型直接进入局部窗口或停在符号/字符串级定位。据此把后续反汇编收敛到窗口 binutils-2.29-o0-objdump:0x1a2f23-0x1a30b8, binutils-2.29-o0-objdump:0x1a3636-0x1a37a8, binutils-2.28-o0-objdump:0x193b50-0x193cc8, binutils-2.28-o0-objdump:0x194295-0x1943e8, binutils-2.28-o0-objdump:0x193cb8-0x193d80。

Windows: `binutils-2.29-o0-objdump:0x1a2f23-0x1a30b8`; `binutils-2.29-o0-objdump:0x1a3636-0x1a37a8`; `binutils-2.28-o0-objdump:0x193b50-0x193cc8`; `binutils-2.28-o0-objdump:0x194295-0x1943e8`; `binutils-2.28-o0-objdump:0x193cb8-0x193d80`; `binutils-2.28-o0-objdump:0x1943be-0x194490`

Trace: symbol/import cmd: `/bin/zsh -lc 'which r2 radare2 rabin2 objdump readelf nm gdb eu-readelf eu-objdump'` | strings cmd: `/bin/zsh -lc "strings -a binutils-2.29-o0-objdump | rg -i 'reloc|out of range|howto|special|section|overflow' | head -120"`

## CVE-2017-8397

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1c7600   -r, --reloc              Display the relocation entries in the file; 1c7646   -R, --dynamic-reloc      Display the dynamic relocation entries in the file; 1d961d   -r, --reloc              Display the relocation entries in the file`。随后 objdump+rg 用模式 `LOAD|Section to Segment; 20820c|20821e|208338|208378|2083b0|208440` 将锚点关联到地址簇 0x306906, 0x208440, 0x307212, 0x319841, 0x21cf40, 0x320174。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0x193600-0x194100, binutils-2.30-o0-objdump:0x1a4c00-0x1a5800, binutils-2.30-o0-objdump:0x1a51d0-0x1a5420, binutils-2.28-o0-objdump:0x193b20-0x193d30, binutils-2.29-o0-objdump:0x1a35e0-0x1a3a20。

Windows: `binutils-2.28-o0-objdump:0x193600-0x194100`; `binutils-2.30-o0-objdump:0x1a4c00-0x1a5800`; `binutils-2.30-o0-objdump:0x1a51d0-0x1a5420`; `binutils-2.28-o0-objdump:0x193b20-0x193d30`; `binutils-2.29-o0-objdump:0x1a35e0-0x1a3a20`; `binutils-2.29.1-o0-objdump:0x1a4020-0x1a4460`

Trace: strings cmd: `/bin/zsh -lc "strings -t x binutils-2.28-o0-objdump | rg 'coff-Intel-(little|big)|reloc'"` | xref cmd: `/bin/zsh -lc "readelf -l binutils-2.28-o0-objdump | rg 'LOAD|Section to Segment' -A8"`

## CVE-2017-8398

readelf/nm 先查符号或导入模式 `strnlen|printf|warn|strlen|sprintf`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d887e  %.*s; 1d9276 %.*s; 1da896  %.*s`。随后 objdump+rg 用模式 `1c94f8|1c9578|1c95d8|strnlen@plt|1c9208|1c880e; 1db620|1db690|1db7c8|strnlen@plt|1db2f8|1db2ed` 将锚点关联到地址簇 0x7345f, 0x73463, 0x73466, 0x7a07a, 0x7a07c, 0x7a080。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0x676e0-0x67980, binutils-2.30-o0-objdump:0x6ac20-0x6b040, binutils-2.29-o0-objdump:0x68a20-0x68e40, binutils-2.29.1-o0-objdump:0x68a20-0x68e40。

Windows: `binutils-2.28-o0-objdump:0x676e0-0x67980`; `binutils-2.30-o0-objdump:0x6ac20-0x6b040`; `binutils-2.29-o0-objdump:0x68a20-0x68e40`; `binutils-2.29.1-o0-objdump:0x68a20-0x68e40`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.28-o0-objdump binutils-2.29-o0-objdump binutils-2.29.1-o0-objdump binutils-2.30-o0-objdump | rg 'strnlen|printf|war...` | strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.29-o0-objdump | rg '%\\.\\*s|no NUL byte|debug_str|debug_line_str|offset too big|index offset|indirect index|Bad...` | xref cmd: `/bin/zsh -lc "objdump -d --no-show-raw-insn binutils-2.28-o0-objdump | rg -C 12 '1c94f8|1c9578|1c95d8|strnlen@plt|1c9208|1c880e'"`

## CVE-2017-8421

readelf/nm 先查符号或导入模式 `get_file_size|bfd_get_reloc_upper_bound|bfd_get_file_flags|bfd_set_error|bfd_fatal|xmalloc|bfd_canonicalize...`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1c8ae8 RELOCATION RECORDS FOR [%s]:; 1c8b05  (none)`。随后 objdump+rg 用模式 `1c8ae8|1c8b05|1c8b0e; 1d8b30|1d8b4d|1d8b56|1d8b69` 将锚点关联到地址簇 0x8568, 0x1c8ae8, 0x8574, 0x8732, 0x1d8b30, 0x8738。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0x654d0-0x65620, binutils-2.29-o0-objdump:0x66700-0x66820, binutils-2.30-o0-objdump:0x688d8-0x68955。

Windows: `binutils-2.28-o0-objdump:0x654d0-0x65620`; `binutils-2.29-o0-objdump:0x66700-0x66820`; `binutils-2.30-o0-objdump:0x688d8-0x68955`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -sW binutils-2.28-o0-objdump | rg 'get_file_size|bfd_get_reloc_upper_bound|bfd_get_file_flags|bfd_set_error|bfd_fatal|xmalloc|bfd_...` | strings cmd: `/bin/zsh -lc "for f in binutils-2.28-o0-objdump binutils-2.29-o0-objdump binutils-2.29.1-o0-objdump binutils-2.30-o0-objdump; do printf '%s\\n' \""'$f";...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.28-o0-objdump | rg -n '1c8ae8|1c8b05|1c8b0e' -C 6"`

## CVE-2017-9038

readelf/nm 先查符号或导入模式 `get_unwind|byte_get|slurp_rel|arm_free|get_data|sprintf|strlen`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `69dcc R_ARM_NONE; 69dd7 R_ARM_PC24; 73dc4 R_ARM_NONE`。随后 objdump+rg 用模式 `8d526|unwind data|8d209|8d598; 8d526|unwind data|8d209|8d598` 将锚点关联到地址簇 0x29299, 0x8d526, 0x29539, 0x30060, 0x9476c, 0x30305。据此把后续反汇编收敛到窗口 binutils-2.28-o0-readelf:0x27380-0x27d20, binutils-2.29-o0-readelf:0x27900-0x28320, binutils-2.30-o0-readelf:0x28400-0x28e50, binutils-2.29.1-o0-readelf:0x27900-0x28320。

Windows: `binutils-2.28-o0-readelf:0x27380-0x27d20`; `binutils-2.29-o0-readelf:0x27900-0x28320`; `binutils-2.30-o0-readelf:0x28400-0x28e50`; `binutils-2.29.1-o0-readelf:0x27900-0x28320`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -sW binutils-2.28-o0-readelf | head -80'` | strings cmd: `/bin/zsh -lc 'strings -tx binutils-2.28-o0-readelf | rg "unwind data|arm unwind|ARM|unwind"'` | xref cmd: `/bin/zsh -lc 'objdump -d --no-show-raw-insn -Mintel binutils-2.29-o0-readelf | rg -n "8d526|unwind data|8d209|8d598"'`

## CVE-2017-9039

readelf/nm 先查符号或导入模式 ` cmalloc| malloc| error|fopen|fread|lseek|fseek|ftell|xmalloc`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `8004e   -l --program-headers   Display the program headers; 80e59   Start of program headers:; 8a44e   -l --program-headers   Display the program headers`。未看到明确 objdump+rg 粗定位，模型直接进入局部窗口或停在符号/字符串级定位。没有显式 start/stop 局部窗口；定位结果主要是 objdump+rg 的上下文地址簇。

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -sW binutils-2.28-o0-readelf | rg ' cmalloc| malloc| error|fopen|fread|lseek|fseek|ftell|xmalloc'"` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.28-o0-readelf | rg 'Too many program headers|Out of memory reading|the file is not that big|program headers'"`

## CVE-2017-9040

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `87458 conflict list found without a dynamic symbol table; 87490 Out of memory allocating space for dynamic conflicts; 91ec0 conflict list found without a dynamic symbol table`。随后 objdump+rg 用模式 `87458|87490|874d1; 91ee8|91f18|91eb0|91f59` 将锚点关联到地址簇 0xa1140, 0x46600, 0x87458, 0xad2d8, 0x47920, 0x91eb0。没有显式 start/stop 局部窗口；定位结果主要是 objdump+rg 的上下文地址簇。

Trace: strings cmd: `/bin/zsh -lc "strings -a binutils-2.28-o0-readelf binutils-2.29-o0-readelf binutils-2.29.1-o0-readelf binutils-2.30-o0-readelf | rg -n \"Overlarge numbe...` | xref cmd: `/bin/zsh -lc 'objdump -d --no-show-raw-insn --section=.text binutils-2.28-o0-readelf | rg -n -C 10 "87458|87490|874d1"'`

## CVE-2017-9043

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND free@GLIBC_2.2.5 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND putchar@GLIBC_2.2.5 (2)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `7b498 Size overflow prevents reading 0x%lx elements of size 0x%lx for %s; 7b4e0 Reading 0x%lx bytes extends past end of file for %s`。随后 objdump+rg 用模式 `# 93a30|# 93a40|# 93b70|# 93ba0|# 93c6f|# 93c76|# 93be0; # 93a30|# 93b60|# 93b90|# 93c5f|# 93c66|# 93bd0` 将锚点关联到地址簇 0x40735, 0x93a40, 0x40b28, 0x408bb, 0x93a30, 0x40cae。据此把后续反汇编收敛到窗口 binutils-2.29-o0-readelf:0x40680-0x40ef0, binutils-2.29.1-o0-readelf:0x40800-0x410a0, binutils-2.30-o0-readelf:0x42240-0x42b00。

Windows: `binutils-2.29-o0-readelf:0x40680-0x40ef0`; `binutils-2.29.1-o0-readelf:0x40800-0x410a0`; `binutils-2.30-o0-readelf:0x42240-0x42b00`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.28-o0-readelf binutils-2.29-o0-readelf binutils-2.29.1-o0-readelf binutils-2.30-o0-readelf'` | strings cmd: `/bin/zsh -lc 'strings -a binutils-2.28-o0-readelf'` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.29-o0-readelf | rg '# 93a30|# 93a40|# 93b70|# 93ba0|# 93c6f|# 93c76|# 93be0'"`

## CVE-2017-9954

readelf/nm 先查符号或导入模式 `getvalue|pass_over|tekhex|bfd_bread|sprintf|strlen|__isoc99|printf; getvalue|pass_over|tekhex|bfd_bread|sprintf|strlen|__isoc99|printf`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1294 opendir; 1c71bb   -h, --[section-]headers  Display the contents of the section headers; 1d71bb   -h, --[section-]headers  Display the contents of the section headers`。随后 objdump+rg 用模式 `1fce48|1fcefd|1fc840|1fcf10|1fce; 1fde88|1fdf3d|1fd880|1fdf50|1fde` 将锚点关联到地址簇 0x111f00, 0x30ee10, 0x111f07, 0xd71f6, 0x1fdee4, 0xd71fd。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0xca000-0xcc400, binutils-2.29-o0-objdump:0xd6800-0xd7440, binutils-2.29.1-o0-objdump:0xd6800-0xd7440, binutils-2.30-o0-objdump:0xdcf00-0xddb40, binutils-2.28-o0-objdump:0xcde00-0xcee40。

Windows: `binutils-2.28-o0-objdump:0xca000-0xcc400`; `binutils-2.29-o0-objdump:0xd6800-0xd7440`; `binutils-2.29.1-o0-objdump:0xd6800-0xd7440`; `binutils-2.30-o0-objdump:0xdcf00-0xddb40`; `binutils-2.28-o0-objdump:0xcde00-0xcee40`; `binutils-2.29-o0-objdump:0xd5200-0xd6880`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.29-o0-objdump | rg 'getvalue|pass_over|tekhex|bfd_bread|sprintf|strlen|__isoc99|printf'"` | strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.28-o0-objdump | rg -i 'tekhex|hex|checksum|invalid|record|chunk|address|END|section'"` | xref cmd: `/bin/zsh -lc "objdump -d --no-show-raw-insn -M intel binutils-2.29-o0-objdump | rg -C 4 '1fce48|1fcefd|1fc840|1fcf10|1fce'"`

## CVE-2017-9955

readelf/nm 先查符号或导入模式 `bfd_get_file_size|_bfd_generic_get_section_contents|bfd_seek|bfd_bread|bfd_get_file_window|bfd_set_error|abort`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1ea910 %B: unable to get decompressed section %A; 1edc60 Warning: %B is truncated: expected core file size >= %lu, found: %lu.`。随后 objdump+rg 用模式 `abort|malloc|free|mmap|memcpy|lseek|read|fread|fseek; 1ea910|ea910|unable to get decompressed` 将锚点关联到地址簇 0xc3731, 0x1ea910, 0xc9883, 0xc98ad, 0xc9d33。据此把后续反汇编收敛到窗口 binutils-2.28-o0-objdump:0xc35e0-0xc39e0, binutils-2.29-o0-objdump:0xcbb40-0xcbf80, binutils-2.30-o0-objdump:0xd22f0-0xd26f0, binutils-2.29.1-o0-objdump:0xcbb30-0xcbf30, binutils-2.28-o0-objdump:0xc3700-0xc3908。

Windows: `binutils-2.28-o0-objdump:0xc35e0-0xc39e0`; `binutils-2.29-o0-objdump:0xcbb40-0xcbf80`; `binutils-2.30-o0-objdump:0xd22f0-0xd26f0`; `binutils-2.29.1-o0-objdump:0xcbb30-0xcbf30`; `binutils-2.28-o0-objdump:0xc3700-0xc3908`; `binutils-2.29-o0-objdump:0xcbd10-0xcbec8`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.28-o0-objdump | rg 'bfd_get_file_size|_bfd_generic_get_section_contents|bfd_seek|bfd_bread|bfd_get_file_window|bfd_...` | strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.28-o0-objdump | rg 'unable to get decompressed section|This should never happen|invalid operation|file size|sect...` | xref cmd: `/bin/zsh -lc "objdump -R binutils-2.28-o0-objdump | rg 'abort|malloc|free|mmap|memcpy|lseek|read|fread|fseek'"`

## CVE-2018-1000876

readelf/nm 先查符号或导入模式 `bfd|symtab|reloc|error|UND|FUNC; "`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `_bfd_elf_get_(symtab|dynamic_symtab|dynamic_reloc)_upper_bound|file too big|File too big|too big|dynamic_re...; _bfd_elf_get_(symtab|dynamic_symtab|dynamic_reloc)_upper_bound|file too big|File too big|too big|dynamic_re...`。随后 objdump+rg 用模式 `objdump"; "` 做候选代码块定位。据此把后续反汇编收敛到窗口 binutils-2.31-o0-objdump:0xf9cc0-0xf9dcf, binutils-2.31-o0-objdump:0xf99f0-0xf9b20, binutils-2.31-o0-objdump:0xf9b60-0xf9d80, binutils-2.33.1-o0-objdump:0x114720-0x114b60, binutils-2.33.1-o0-objdump:0x114b50-0x114b90。

Windows: `binutils-2.31-o0-objdump:0xf9cc0-0xf9dcf`; `binutils-2.31-o0-objdump:0xf99f0-0xf9b20`; `binutils-2.31-o0-objdump:0xf9b60-0xf9d80`; `binutils-2.33.1-o0-objdump:0x114720-0x114b60`; `binutils-2.33.1-o0-objdump:0x114b50-0x114b90`; `binutils-2.30-o0-objdump:0x109b03-0x109cb0`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.33-o0-objdump | head -40'` | strings cmd: `/bin/zsh -lc "strings -a binutils-2.32-o0-objdump | rg '_bfd_elf_get_(symtab|dynamic_symtab|dynamic_reloc)_upper_bound|file too big|File too big|too big...` | xref cmd: `/bin/zsh -lc "rg --files | rg 'objdump"'$|objdump$|2'"\\.33|2\\.32'"`

## CVE-2018-10372

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1bead8 Section %s too small for offset and size tables; 1beb40 Row index (%u) is larger than number of used entries (%u); 1e1790 Section %s too small for offset and size tables`。随后 objdump+rg 用模式 `1beb80|1beb40|1bebb8; 1c5988|1c5948|1c59c0` 将锚点关联到地址簇 0x8b6eb, 0x8b6ee, 0x1b8378, 0x8abf8, 0x8abfb, 0x1bf1f8。没有显式 start/stop 局部窗口；定位结果主要是 objdump+rg 的上下文地址簇。

Trace: strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.32-o0-objdump | rg 'Signature \\(%p\\) extends beyond end of space in section|Row index|too small for offset and...` | xref cmd: `/bin/zsh -lc "objdump -d --no-show-raw-insn binutils-2.32-o0-objdump | rg -B45 -A85 '1beb80|1beb40|1bebb8'"`

## CVE-2018-10373

readelf/nm 先查符号或导入模式 `strdup|bfd_error|dcgettext|fprintf|printf; strdup|bfd_error|dcgettext|fprintf|printf`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1dc768 <unknown>; 1e1c8a   ID: <unknown>; 1b9948 <unknown>`。随后 objdump+rg 用模式 `1e8390|1e83cb; 1e8b48|1e8b83` 将锚点关联到地址簇 0x12ff87, 0x12ff8a, 0x12ff8d, 0x13524a, 0x13524d, 0x135250。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x13fa70-0x13fb10, binutils-2.31-o0-objdump:0x12ff40-0x12ffe0, binutils-2.31.1-o0-objdump:0x12ff40-0x12ffe0, binutils-2.32-o0-objdump:0x135200-0x1352a8。

Windows: `binutils-2.30-o0-objdump:0x13fa70-0x13fb10`; `binutils-2.31-o0-objdump:0x12ff40-0x12ffe0`; `binutils-2.31.1-o0-objdump:0x12ff40-0x12ffe0`; `binutils-2.32-o0-objdump:0x135200-0x1352a8`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.30-o0-objdump | rg 'strdup|bfd_error|dcgettext|fprintf|printf'"` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.30-o0-objdump | rg '<unknown>|bad file number|mangled line number|DWARF error'"` | xref cmd: `/bin/zsh -lc "objdump -d --no-show-raw-insn -M intel binutils-2.31-o0-objdump | rg '1e8390|1e83cb' -C 8"`

## CVE-2018-17358

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1ff823 unsupported .stab relocation; 23e416 unsupported .stab relocation`。随后 objdump+rg 将锚点关联到地址簇 0x170812, 0x23e416, 0x23e433, 0x170149, 0x2422f6, 0x242313。据此把后续反汇编收敛到窗口 binutils-2.31.1-o0-objdump:0x18c340-0x18c4f0, binutils-2.41-o0-objdump:0x105dc0-0x105ee8, binutils-2.42-o0-objdump:0x1063b8-0x1064e0, binutils-2.43-o0-objdump:0x109730-0x109850, binutils-2.31.1-o0-objdump:0x18c4e0-0x18c620。

Windows: `binutils-2.31.1-o0-objdump:0x18c340-0x18c4f0`; `binutils-2.41-o0-objdump:0x105dc0-0x105ee8`; `binutils-2.42-o0-objdump:0x1063b8-0x1064e0`; `binutils-2.43-o0-objdump:0x109730-0x109850`; `binutils-2.31.1-o0-objdump:0x18c4e0-0x18c620`; `binutils-2.31.1-o0-objdump:0x18bf00-0x18c360`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.31.1-o0-objdump | head -60'` | strings cmd: `/bin/zsh -lc "strings -a binutils-2.31.1-o0-objdump | rg -n \"unsupported \\.stab relocation|\\.stab|N_SO|N_FUN\""` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.41-o0-objdump | rg -n \"23e416|unsupported \\.stab relocation\" -C 20"`

## CVE-2018-17360

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1b8288 Encoded size of 0 is too small to read; 1bacb8 The length field (0x%lx) in the debug_line header is wrong - the section is too small; 1bf108 Encoded size of 0 is too small to read`。随后 objdump+rg 用模式 `1eb761|1eb9b0|1eed39|1eef88; 1e4dc1|1e5010|1e8359|1e85a8` 将锚点关联到地址簇 0x244612, 0x1eb9b0, 0x280957, 0x249956, 0x1e5010, 0x286337。据此把后续反汇编收敛到窗口 binutils-2.31.1-o0-objdump:0x151f00-0x153200, binutils-2.31.1-o0-objdump:0x176e00-0x178200, binutils-2.32-o0-objdump:0x17c300-0x17d600, binutils-2.32-o0-objdump:0x157300-0x158600, binutils-2.31.1-o0-objdump:0x1773e0-0x1774a0。

Windows: `binutils-2.31.1-o0-objdump:0x151f00-0x153200`; `binutils-2.31.1-o0-objdump:0x176e00-0x178200`; `binutils-2.32-o0-objdump:0x17c300-0x17d600`; `binutils-2.32-o0-objdump:0x157300-0x158600`; `binutils-2.31.1-o0-objdump:0x1773e0-0x1774a0`; `binutils-2.32-o0-objdump:0x157f80-0x158050`

Trace: strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.32-o0-objdump | rg 'export table|Export Address Table|Invalid Export Address Table|does not fit into that sectio...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.31.1-o0-objdump | rg -n '1eb761|1eb9b0|1eed39|1eef88'"`

## CVE-2018-18605

readelf/nm 先查符号或导入模式 `_bfd_add_merge_section|sec_merge|bfd_get_full_section_contents|abort|memset; abort|memset|calloc|malloc|free|memcmp|strlen|strcmp`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `150cc4 .reloc; 175bcf .reloc; 16bc2f .reloc`。随后 objdump+rg 用模式 `1ea1e0|1ea150|merge.c|_bfd_add_merge_section; 1f00e0|1f0090|merge.c|_bfd_add_merge_section` 将锚点关联到地址簇 0x18bf68, 0x18bf6c, 0x18bf70, 0x186ab6, 0x186aba, 0x186abe。据此把后续反汇编收敛到窗口 binutils-2.31-o0-objdump:0x186c60-0x186f80, binutils-2.32-o0-objdump:0x18c150-0x18c4a0, binutils-2.33.1-o0-objdump:0x1a2100-0x1a2490。

Windows: `binutils-2.31-o0-objdump:0x186c60-0x186f80`; `binutils-2.32-o0-objdump:0x18c150-0x18c4a0`; `binutils-2.33.1-o0-objdump:0x1a2100-0x1a2490`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -sW binutils-2.31-o0-objdump | rg '_bfd_add_merge_section|sec_merge|bfd_get_full_section_contents|abort|memset'"` | strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.31-o0-objdump | rg -i 'merge|SEC_MERGE|section|reloc|strings' | head -120"` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.32-o0-objdump | rg '1ea1e0|1ea150|merge.c|_bfd_add_merge_section' -C 4"`

## CVE-2018-18606

readelf/nm 先查符号或导入模式 `bfd_add_merge|merge|sprintf|strlen|malloc|memset|bfd_get_full_section_contents|sec_merge_init; bfd_add_merge|merge|sprintf|strlen|malloc|memset|bfd_get_full_section_contents|sec_merge_init`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `150cc4 .reloc; 175bcf .reloc; 16bc2f .reloc`。随后 objdump+rg 用模式 `1f00e0|1f0090|1f0120|1e56b0|1e1160; 1ea1e0|1ea150|1ea220|1df3a8|1da560` 将锚点关联到地址簇 0xbe353, 0x1e1160, 0xecd74, 0xbf0b6, 0x1da560, 0xf1833。据此把后续反汇编收敛到窗口 binutils-2.31-o0-objdump:0x185f00-0x187400, binutils-2.32-o0-objdump:0x18bdb0-0x18d200, binutils-2.33.1-o0-objdump:0x1a1d60-0x1a3200, binutils-2.31-o0-objdump:0x186c80-0x187060, binutils-2.32-o0-objdump:0x18c1c0-0x18c330。

Windows: `binutils-2.31-o0-objdump:0x185f00-0x187400`; `binutils-2.32-o0-objdump:0x18bdb0-0x18d200`; `binutils-2.33.1-o0-objdump:0x1a1d60-0x1a3200`; `binutils-2.31-o0-objdump:0x186c80-0x187060`; `binutils-2.32-o0-objdump:0x18c1c0-0x18c330`; `binutils-2.33.1-o0-objdump:0x1a2170-0x1a22e0`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.31-o0-objdump | rg "bfd_add_merge|merge|sprintf|strlen|malloc|memset|bfd_get_full_section_contents|sec_merge_init"'` | strings cmd: `/bin/zsh -lc 'strings -a -tx binutils-2.31-o0-objdump | rg -i "merge|alignment|strings|section|reloc|bfd_get_full_section_contents"'` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.31-o0-objdump | rg "1f00e0|1f0090|1f0120|1e56b0|1e1160"'`

## CVE-2018-18607

readelf/nm 先查符号或导入模式 `elf_link_input_bfd|sprintf|strlen|BFD|tls_sec|STT_TLS|assert`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `tls_sec|STT_TLS|ELF_ST_INFO|BFD_ASSERT|assert|elf_link_input_bfd|PT_TLS; tls_sec|STT_TLS|ELF_ST_INFO|BFD_ASSERT|assert|elf_link_input_bfd|PT_TLS`。随后 objdump+rg 用模式 `1e1340|1e00a0|1da1c8|__assert_fail; 1e74c0|1e6260|1e0ea8|__assert_fail` 将锚点关联到地址簇 0x665, 0x667, 0x2ddd80, 0x669, 0x671, 0x2f1d80。据此把后续反汇编收敛到窗口 binutils-2.31-o0-objdump:0x11b1d0-0x11b3a0, binutils-2.31-o0-objdump:0x119f20-0x11a120, binutils-2.32-o0-objdump:0x1200a0-0x1202a0, binutils-2.32-o0-objdump:0x121420-0x121530, binutils-2.32-o0-objdump:0x121350-0x1214c0。

Windows: `binutils-2.31-o0-objdump:0x11b1d0-0x11b3a0`; `binutils-2.31-o0-objdump:0x119f20-0x11a120`; `binutils-2.32-o0-objdump:0x1200a0-0x1202a0`; `binutils-2.32-o0-objdump:0x121420-0x121530`; `binutils-2.32-o0-objdump:0x121350-0x1214c0`; `binutils-2.32-o0-objdump:0x120250-0x120380`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.31-o0-objdump binutils-2.32-o0-objdump binutils-2.33-o0-objdump binutils-2.33.1-o0-objdump | rg 'elf_link_input_bfd...` | strings cmd: `/bin/zsh -lc "strings -a binutils-2.31-o0-objdump | rg -n 'tls_sec|STT_TLS|ELF_ST_INFO|BFD_ASSERT|assert|elf_link_input_bfd|PT_TLS'"` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.32-o0-objdump | rg -n '1e1340|1e00a0|1da1c8|__assert_fail'"`

## CVE-2018-19932

readelf/nm 先查符号或导入模式 `bfd_set_error|abort|free|malloc|zalloc; bfd_set_error|abort|free|malloc|zalloc`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `map->count|BFD_ASSERT|Internal error|bfd_error_bad_value|bad value|elf.c; map->count|BFD_ASSERT|Internal error|bfd_error_bad_value|bad value|elf.c`。随后 objdump+rg 用模式 `203108|203148|2038f0|1fe168; 1df6f8|1df738|1e0010|1da0c8` 将锚点关联到地址簇 0xcc3a1, 0x1fe168, 0x10374c, 0xf80b3, 0x1df6f8, 0xf82d8。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x105e00-0x107300, binutils-2.31-o0-objdump:0xf5a00-0xf7200, binutils-2.32-o0-objdump:0xfaa00-0xfc100, binutils-2.33.1-o0-objdump:0x110600-0x112200, binutils-2.33.1-o0-objdump:0x10d400-0x10e600。

Windows: `binutils-2.30-o0-objdump:0x105e00-0x107300`; `binutils-2.31-o0-objdump:0xf5a00-0xf7200`; `binutils-2.32-o0-objdump:0xfaa00-0xfc100`; `binutils-2.33.1-o0-objdump:0x110600-0x112200`; `binutils-2.33.1-o0-objdump:0x10d400-0x10e600`; `binutils-2.29.1-o0-objdump:0xff000-0x100800`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.31-o0-objdump | rg 'bfd_set_error|abort|free|malloc|zalloc'"` | strings cmd: `/bin/zsh -lc "strings -a binutils-2.31-o0-objdump | rg 'map->count|BFD_ASSERT|Internal error|bfd_error_bad_value|bad value|elf.c'"` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.30-o0-objdump | rg '203108|203148|2038f0|1fe168'"`

## CVE-2018-20002

readelf/nm 先查符号或导入模式 `"; "`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `13d0d7 synthetic; 13d150  List symbols in [file(s)] (a.out by default).`。未看到明确 objdump+rg 粗定位，模型直接进入局部窗口或停在符号/字符串级定位。没有显式 start/stop 局部窗口；定位结果主要是 objdump+rg 的上下文地址簇。

Trace: symbol/import cmd: `/bin/zsh -lc 'for f in binutils-2.31-o0-nm binutils-2.32-o0-nm binutils-2.33-o0-nm binutils-2.33.1-o0-nm; do if [ -e "$f" ]; then printf '"'%s exists\\n...` | strings cmd: `/bin/zsh -lc "for f in binutils-2.31-o0-nm binutils-2.32-o0-nm binutils-2.33.1-o0-nm; do printf '%s\\n' \""'$f"; strings -a -tx "$f" | rg '"'no symbols|...`

## CVE-2018-20651

readelf/nm 先查符号或导入模式 `"`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1984261 .dynamic; 1987884 .dynamic`。随后 objdump+rg 用模式 `"; # 1e6df0|# 1e6e50|# 1e6e78|# 1e6f58` 将锚点关联到地址簇 0x62523, 0x96060, 0x96070, 0x10a5b0, 0x1e6e50, 0x125e51。据此把后续反汇编收敛到窗口 binutils-2.31.1-o0-objdump:0x109000-0x10c500, binutils-2.33.1-o0-objdump:0x123800-0x128000, binutils-2.31.1-o0-objdump:0xe79f0-0xe7bb0, binutils-2.31.1-o0-objdump:0xec580-0xec690, binutils-2.31.1-o0-objdump:0xe8960-0xe8a80。

Windows: `binutils-2.31.1-o0-objdump:0x109000-0x10c500`; `binutils-2.33.1-o0-objdump:0x123800-0x128000`; `binutils-2.31.1-o0-objdump:0xe79f0-0xe7bb0`; `binutils-2.31.1-o0-objdump:0xec580-0xec690`; `binutils-2.31.1-o0-objdump:0xe8960-0xe8a80`; `binutils-2.31.1-o0-objdump:0x107000-0x10c100`

Trace: symbol/import cmd: `/bin/zsh -lc "for f in binutils-2.31.1-o0-objdump binutils-2.32-o0-objdump binutils-2.33.1-o0-objdump; do printf '%s\\n' \""'$f"; readelf -rW "$f" | rg ...` | strings cmd: `/bin/zsh -lc "for f in binutils-2.31.1-o0-objdump binutils-2.32-o0-objdump binutils-2.33.1-o0-objdump; do printf '%s\\n' \""'$f"; strings -td "$f" | rg ...` | xref cmd: `/bin/zsh -lc "for f in binutils-2.31.1-o0-objdump binutils-2.32-o0-objdump binutils-2.33.1-o0-objdump; do printf '%s\\n' \""'$f"; objdump -d -M intel "$...`

## CVE-2018-20671

readelf/nm 先查符号或导入模式 `bfd_get_file_size|malloc|bfd_get_full_section_contents|printf|load_specific_debug_section; "`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1be759 Can't get contents for section '%s'.; 1e5088 %pB: invalid size field in group section header: %#lx; 1cf999 Section '%s' has an invalid size: %#llx.`。随后 objdump+rg 用模式 `1b78|1b77|1b79|5f; 1be7|1be6|1be8` 将锚点关联到地址簇 0xd85fe, 0xd865f, 0xd87b6, 0x6194f, 0x62df3, 0x1be608。据此把后续反汇编收敛到窗口 binutils-2.32-o0-objdump:0x65920-0x65d00, binutils-2.30-o0-objdump:0x66360-0x66770, binutils-2.31.1-o0-objdump:0x65480-0x65880, binutils-2.33.1-o0-objdump:0x66ae0-0x66f50。

Windows: `binutils-2.32-o0-objdump:0x65920-0x65d00`; `binutils-2.30-o0-objdump:0x66360-0x66770`; `binutils-2.31.1-o0-objdump:0x65480-0x65880`; `binutils-2.33.1-o0-objdump:0x66ae0-0x66f50`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.31.1-o0-objdump | rg 'bfd_get_file_size|malloc|bfd_get_full_section_contents|printf|load_specific_debug_section'"` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.31.1-o0-objdump | rg \"invalid size|Can't get contents|Section '%s'\""` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.32-o0-objdump | rg "1b78|1b77|1b79|5f"'`

## CVE-2018-6543

readelf/nm 先查符号或导入模式 `"; "`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d9550                            Display DWARF info in the file; 1da761 Can't get contents for section '%s'.`。随后 objdump+rg 用模式 `1be759|malloc@plt|bfd_get_full_section_contents|Can.t get contents; 1b78b1|malloc@plt|bfd_get_full_section_contents|Can.t get contents` 将锚点关联到地址簇 0x71755, 0x1c9828, 0x71803, 0x72422, 0x1c2b28, 0x72470。据此把后续反汇编收敛到窗口 binutils-2.31-o0-objdump:0x65440-0x65720, binutils-2.31.1-o0-objdump:0x65440-0x65720, binutils-2.32-o0-objdump:0x65a40-0x65d40, binutils-2.30-o0-objdump:0x663e0-0x66690, binutils-2.32-o0-objdump:0x65a69-0x65b50。

Windows: `binutils-2.31-o0-objdump:0x65440-0x65720`; `binutils-2.31.1-o0-objdump:0x65440-0x65720`; `binutils-2.32-o0-objdump:0x65a40-0x65d40`; `binutils-2.30-o0-objdump:0x663e0-0x66690`; `binutils-2.32-o0-objdump:0x65a69-0x65b50`; `binutils-2.31.1-o0-objdump:0x65570-0x65670`

Trace: symbol/import cmd: `/bin/zsh -lc 'for f in binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump binutils-2.32-o0-objdump; do readelf -Ws "$f" | rg '...` | strings cmd: `/bin/zsh -lc "for f in binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump binutils-2.32-o0-objdump; do printf '%s\\n' \""'$f";...` | xref cmd: `/bin/zsh -lc "objdump -d binutils-2.31-o0-objdump | rg -n '1be759|malloc@plt|bfd_get_full_section_contents|Can.t get contents' -C 8"`

## CVE-2018-6759

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1e0fe0 The debuglink filename is corrupt/missing; 1e1030 .gnu_debuglink`。随后 objdump+rg 用模式 `strnlen|memcpy|malloc|free|__assert_fail|bfd|plt; <.*@plt>|strnlen|free|malloc|memcpy|__assert_fail` 将锚点关联到地址簇 0x5, 0x7, 0x13, 0x12, 0x17, 0x3040。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0xd3d40-0xd4080, binutils-2.31.1-o0-objdump:0xd3d40-0xd4080, binutils-2.31-o0-objdump:0xd3d40-0xd4080, binutils-2.32-o0-objdump:0xd3d40-0xd4080, binutils-2.31-o0-objdump:0xc3180-0xc3560。

Windows: `binutils-2.30-o0-objdump:0xd3d40-0xd4080`; `binutils-2.31.1-o0-objdump:0xd3d40-0xd4080`; `binutils-2.31-o0-objdump:0xd3d40-0xd4080`; `binutils-2.32-o0-objdump:0xd3d40-0xd4080`; `binutils-2.31-o0-objdump:0xc3180-0xc3560`; `binutils-2.31.1-o0-objdump:0xc3180-0xc3560`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -sW binutils-2.30-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc "strings -t x binutils-2.30-o0-objdump | rg 'gnu_debug(link|altlink)|debuglink|debugaltlink'"` | xref cmd: `/bin/zsh -lc "objdump -d -j .plt binutils-2.30-o0-objdump | rg -n 'strnlen|memcpy|malloc|free|__assert_fail|bfd|plt'"`

## CVE-2018-6872

readelf/nm 先查符号或导入模式 `elf_parse_notes|sprintf|strlen|bfd|note; elf_parse_notes|sprintf|strlen|bfd|note`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d9b15                                   The STYLE, if specified, can be `auto', `gnu',; 1d9b66                                   `lucid', `arm', `hp', `edg', `gnu-v3', `java'; 1bdb15                                   The STYLE, if specified, can be `auto', `gnu',`。未看到明确 objdump+rg 粗定位，模型直接进入局部窗口或停在符号/字符串级定位。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x10fbc9-0x110080, binutils-2.31-o0-objdump:0xffad0-0x100000, binutils-2.31.1-o0-objdump:0xffad0-0x100000, binutils-2.32-o0-objdump:0x105ab8-0x105fe8。

Windows: `binutils-2.30-o0-objdump:0x10fbc9-0x110080`; `binutils-2.31-o0-objdump:0xffad0-0x100000`; `binutils-2.31.1-o0-objdump:0xffad0-0x100000`; `binutils-2.32-o0-objdump:0x105ab8-0x105fe8`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.30-o0-objdump | rg 'elf_parse_notes|sprintf|strlen|bfd|note'"` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.30-o0-objdump | rg -i 'note|align|build.id|gnu'"`

## CVE-2018-7208

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `20ab30 /home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/bfd/coffgen.c; 1e66b0 /home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/bfd/coffgen.c; 1ed090 /home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/bfd/coffgen.c`。随后 objdump+rg 用模式 `1ed090|coffgen; 20ab30|coffgen` 将锚点关联到地址簇 0x1627b6, 0x1627ba, 0x1627bc, 0x17fafe, 0x17fb02, 0x17fb04。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x182360-0x182660, binutils-2.31-o0-objdump:0x165020-0x165330, binutils-2.31.1-o0-objdump:0x165020-0x165330, binutils-2.32-o0-objdump:0x16a370-0x16a690。

Windows: `binutils-2.30-o0-objdump:0x182360-0x182660`; `binutils-2.31-o0-objdump:0x165020-0x165330`; `binutils-2.31.1-o0-objdump:0x165020-0x165330`; `binutils-2.32-o0-objdump:0x16a370-0x16a690`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -sW binutils-2.30-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.30-o0-objdump | rg 'coff_pointerize_aux|auxent->is_sym|coffgen|x_tagndx|obj_raw_syment|pointerize'"` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.31.1-o0-objdump | rg '1ed090|coffgen' -C 3"`

## CVE-2018-7568

readelf/nm 先查符号或导入模式 `parse_die|strnlen|bfd_get|sprintf|strlen|abort|__stack|FUNC|UND`。随后 objdump+rg 用模式 `strnlen@plt; strnlen@plt` 将锚点关联到地址簇 0x1e7c38, 0x1e7c33, 0x197791, 0x1e7578, 0x1e7573, 0x204ca0。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x13ceb0-0x13d0d8, binutils-2.31.1-o0-objdump:0x12d390-0x12d5b9, binutils-2.32-o0-objdump:0x132630-0x132859, binutils-2.31-o0-objdump:0x12d390-0x12d5b9。

Windows: `binutils-2.30-o0-objdump:0x13ceb0-0x13d0d8`; `binutils-2.31.1-o0-objdump:0x12d390-0x12d5b9`; `binutils-2.32-o0-objdump:0x132630-0x132859`; `binutils-2.31-o0-objdump:0x12d390-0x12d5b9`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump binutils-2.32-o0-objdump | rg -n "parse_die|strnl...` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.31.1-o0-objdump | rg -n -C 45 "strnlen@plt"'`

## CVE-2018-7569

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1d9c2a   -z, --disassemble-zeroes       Do not skip blocks of zeroes when disassembling; 1db8d8 %c%s byte block:; 1bdc2a   -z, --disassemble-zeroes       Do not skip blocks of zeroes when disassembling`。随后 objdump+rg 用模式 `205a88|Dwarf Error|DWARF error; 1e8290|Dwarf Error|DWARF error` 将锚点关联到地址簇 0x13ed93, 0x13ed97, 0x13ed9b, 0x12f2a5, 0x12f2a9, 0x12f2ad。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x13ecf0-0x13fa80, binutils-2.31-o0-objdump:0x12f200-0x12ff90, binutils-2.30-o0-objdump:0x13df90-0x13e010, binutils-2.32-o0-objdump:0x133680-0x133760, binutils-2.31.1-o0-objdump:0x12e470-0x12e520。

Windows: `binutils-2.30-o0-objdump:0x13ecf0-0x13fa80`; `binutils-2.31-o0-objdump:0x12f200-0x12ff90`; `binutils-2.30-o0-objdump:0x13df90-0x13e010`; `binutils-2.32-o0-objdump:0x133680-0x133760`; `binutils-2.31.1-o0-objdump:0x12e470-0x12e520`; `binutils-2.31-o0-objdump:0x12e470-0x12e4f0`

Trace: strings cmd: `/bin/zsh -lc "strings -tx binutils-2.30-o0-objdump | rg 'DWARF error: info pointer|FORM block|extends beyond end|attributes|block'"` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.30-o0-objdump | rg -C 5 '205a88|Dwarf Error|DWARF error'"`

## CVE-2018-7570

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 搜索模式 `__ehdr_start|non-load segment|assign_file_positions|RELRO|GNU_RELRO|file header|program header|PT_GNU_RELRO...; __ehdr_start|non-load segment|assign_file_positions|RELRO|GNU_RELRO|file header|program header|PT_GNU_RELRO...`。随后 objdump+rg 用模式 `1e6160|1e61a0|1e5a78|1e5a64|1e412a; 1e67a0|1e67e0|1e60b0|1e609c|1e4652` 将锚点关联到地址簇 0xd9e0a, 0x1e412a, 0xf391c, 0x1e4652, 0xde585, 0x1ddd12。据此把后续反汇编收敛到窗口 binutils-2.30-o0-objdump:0x102e00-0x104700, binutils-2.31-o0-objdump:0xf2a00-0xf4300, binutils-2.31.1-o0-objdump:0xf2a00-0xf4300, binutils-2.32-o0-objdump:0xf7800-0xf9100, binutils-2.30-o0-objdump:0x103e80-0x104190。

Windows: `binutils-2.30-o0-objdump:0x102e00-0x104700`; `binutils-2.31-o0-objdump:0xf2a00-0xf4300`; `binutils-2.31.1-o0-objdump:0xf2a00-0xf4300`; `binutils-2.32-o0-objdump:0xf7800-0xf9100`; `binutils-2.30-o0-objdump:0x103e80-0x104190`; `binutils-2.31-o0-objdump:0xf3a70-0xf3e90`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.30-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc 'strings -a -t x binutils-2.30-o0-objdump | rg -n "__ehdr_start|non-load segment|assign_file_positions|RELRO|GNU_RELRO|file header|program ...` | xref cmd: `/bin/zsh -lc 'objdump -d --no-show-raw-insn binutils-2.31-o0-objdump | rg "1e6160|1e61a0|1e5a78|1e5a64|1e412a"'`

## CVE-2018-7643

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1df258     Offset   Begin            End              Expression; 1df298 There is a hole [0x%lx - 0x%lx] in .debug_loc section.`。随后 objdump+rg 用模式 `1bcb10|1bcad0|1bcb40|1bcb70; 1c3918|1c38d8|1c3948|1c3978` 将锚点关联到地址簇 0x80d9e, 0x80da2, 0x80da6, 0x80419, 0x8041d, 0x80421。据此把后续反汇编收敛到窗口 binutils-2.31-o0-objdump:0x80400-0x804c5, binutils-2.31.1-o0-objdump:0x80400-0x804c5, binutils-2.30-o0-objdump:0x811d0-0x81295, binutils-2.32-o0-objdump:0x80d85-0x80e4a, binutils-2.30-o0-objdump:0x81239-0x81385。

Windows: `binutils-2.31-o0-objdump:0x80400-0x804c5`; `binutils-2.31.1-o0-objdump:0x80400-0x804c5`; `binutils-2.30-o0-objdump:0x811d0-0x81295`; `binutils-2.32-o0-objdump:0x80d85-0x80e4a`; `binutils-2.30-o0-objdump:0x81239-0x81385`; `binutils-2.31-o0-objdump:0x804a8-0x805f5`

Trace: strings cmd: `/bin/zsh -lc "for b in binutils-2.30-o0-objdump binutils-2.31-o0-objdump binutils-2.31.1-o0-objdump binutils-2.32-o0-objdump; do printf '%s\\n' \""'$b";...` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.32-o0-objdump | rg -C 6 '1bcb10|1bcad0|1bcb40|1bcb70'"`

## CVE-2018-8945

readelf/nm 先查符号或导入模式 `bfd_malloc|bfd_get_section_contents|bfd_get_file_size|bfd_set_error|_bfd_error_handler|malloc|free; 1e7540|1e7578|bfd_malloc|bfd_get_section_contents|error|malloc`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1db5e8 DW_FORM_strp offset too big: %s; 1db609 <offset is too big>; 1bf5e8 DW_FORM_strp offset too big: %s`。随后 objdump+rg 用模式 `1e7540|1e7578|1e0c9c|1e0e01` 将锚点关联到地址簇 0x197686, 0x1e7540, 0x197773。据此把后续反汇编收敛到窗口 binutils-2.31-o0-objdump:0x124300-0x124700, binutils-2.31.1-o0-objdump:0x124300-0x124700, binutils-2.32-o0-objdump:0x124300-0x124700, binutils-2.30-o0-objdump:0x124100-0x124600, binutils-2.30-o0-objdump:0x133f80-0x134280。

Windows: `binutils-2.31-o0-objdump:0x124300-0x124700`; `binutils-2.31.1-o0-objdump:0x124300-0x124700`; `binutils-2.32-o0-objdump:0x124300-0x124700`; `binutils-2.30-o0-objdump:0x124100-0x124600`; `binutils-2.30-o0-objdump:0x133f80-0x134280`; `binutils-2.32-o0-objdump:0x12a580-0x12a900`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.30-o0-objdump | head -40'` | strings cmd: `/bin/zsh -lc 'strings -a -t x binutils-2.30-o0-objdump | rg "attribute section|too big|string table|file too big|section.*big|invalid operation"'` | xref cmd: `/bin/zsh -lc 'objdump -d -M intel binutils-2.31-o0-objdump | rg -n "1e7540|1e7578|1e0c9c|1e0e01"'`

## CVE-2019-17451

readelf/nm 先查符号或导入模式 `UND; malloc|free|memcpy|memset|str|printf|open|read|close|zlib|compress`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1b649b   --dwarf[=rawline,=decodedline,=info,=abbrev,=pubnames,=aranges,=macro,=frames,; 1b6591                            Display DWARF info in the file; 1de4e2   --dwarf[=rawline,=decodedline,=info,=abbrev,=pubnames,=aranges,=macro,=frames,`。随后 objdump+rg 用模式 `1e1f48|1e1f70|1e1fc8|1df1ab|1df304|1dadd7|1dae36; 1fce68|1fce90|1fcee8|1f99a3|1f9afc|1f55f7|1f5656` 将锚点关联到地址簇 0xc56e9, 0x1dadd7, 0xc6104, 0xe3c88, 0x1f55f7, 0xe46d1。据此把后续反汇编收敛到窗口 binutils-2.32-o0-objdump:0x132f00-0x133800, binutils-2.35-o0-objdump:0x155f00-0x156900, binutils-2.32-o0-objdump:0x135f00-0x136500, binutils-2.32-o0-objdump:0x137800-0x137d80, binutils-2.35-o0-objdump:0x15dc00-0x15e600。

Windows: `binutils-2.32-o0-objdump:0x132f00-0x133800`; `binutils-2.35-o0-objdump:0x155f00-0x156900`; `binutils-2.32-o0-objdump:0x135f00-0x136500`; `binutils-2.32-o0-objdump:0x137800-0x137d80`; `binutils-2.35-o0-objdump:0x15dc00-0x15e600`; `binutils-2.32-o0-objdump:0xba520-0xba5d0`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.32-o0-objdump | rg 'UND' | rg 'malloc|calloc|realloc|free|strlen|strcmp|bfd|printf|sprintf|memcpy|memset|fopen|open...` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.32-o0-objdump | rg 'debug_info|gnu_debuglink|build-id|not enough memory|file format not recognized|bfd_error_no...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.32-o0-objdump | rg '1e1f48|1e1f70|1e1fc8|1df1ab|1df304|1dadd7|1dae36'"`

## CVE-2020-16590

readelf/nm 先查符号或导入模式 ` get_num_dynamic_syms| free@| get_dynamic_data| buckets|chains; free|malloc|calloc|realloc|fread|printf|strlen|strcmp|memcpy|memset`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `778080 Out of memory allocating %s bytes for %s; 778362 out of memory parsing relocs`。随后 objdump+rg 用模式 `c6df0|c6e18|c6e40|c6e69|c6eb0|c7d79|c7dc1|c7e01; free@plt|<free@plt>` 将锚点关联到地址簇 0x36333, 0xc6df0, 0x36350, 0x64067, 0x64073, 0x64098。据此把后续反汇编收敛到窗口 binutils-2.35-o0-readelf:0x2fc00-0x31650, binutils-2.35.1-o0-readelf:0x2fc00-0x31650, binutils-2.35.2-o0-readelf:0x2fc00-0x31650, binutils-2.35-o0-readelf:0x30380-0x30ff5, binutils-2.35.2-o0-readelf:0x30380-0x30ff5。

Windows: `binutils-2.35-o0-readelf:0x2fc00-0x31650`; `binutils-2.35.1-o0-readelf:0x2fc00-0x31650`; `binutils-2.35.2-o0-readelf:0x2fc00-0x31650`; `binutils-2.35-o0-readelf:0x30380-0x30ff5`; `binutils-2.35.2-o0-readelf:0x30380-0x30ff5`; `binutils-2.35.1-o0-readelf:0x30380-0x30ff5`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -sW binutils-2.35-o0-readelf | rg ' get_num_dynamic_syms| free@| get_dynamic_data| buckets|chains'"` | strings cmd: `/bin/zsh -lc "strings -td binutils-2.35-o0-readelf | rg -i 'hash|chain|bucket|dynamic|symbol table|out of memory|processor specific|operating system|Inv...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.35-o0-readelf | rg -n 'c6df0|c6e18|c6e40|c6e69|c6eb0|c7d79|c7dc1|c7e01'"`

## CVE-2020-16591

readelf/nm 先查符号或导入模式 `get_num_dynamic_syms|get_dynamic_data|UND|free|malloc|error|warn|byte_get; get_num_dynamic_syms|get_dynamic_data|UND|free|malloc|error|warn|byte_get`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `a8010 %s:%lu: end of data encountered whilst reading LEB; a8048 %s:%lu: read LEB value is too large to store in destination variable; aa010 %s:%lu: end of data encountered whilst reading LEB`。随后 objdump+rg 用模式 `c8df0|c8e18|c8e40|c8d58|c9d79; c6df0|c6e18|c6e40|c6d58|c7d79` 将锚点关联到地址簇 0x30282, 0x30284, 0x30287。据此把后续反汇编收敛到窗口 binutils-2.35-o0-readelf:0x2fc00-0x31050, binutils-2.35-o0-readelf:0x30660-0x30d10, binutils-2.35.1-o0-readelf:0x30660-0x30d10, binutils-2.35.2-o0-readelf:0x30660-0x30d10, binutils-2.35.1-o0-readelf:0x303c0-0x30690。

Windows: `binutils-2.35-o0-readelf:0x2fc00-0x31050`; `binutils-2.35-o0-readelf:0x30660-0x30d10`; `binutils-2.35.1-o0-readelf:0x30660-0x30d10`; `binutils-2.35.2-o0-readelf:0x30660-0x30d10`; `binutils-2.35.1-o0-readelf:0x303c0-0x30690`; `binutils-2.35-o0-readelf:0x303c0-0x30690`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.36-o0-readelf | rg 'get_num_dynamic_syms|get_dynamic_data|UND|free|malloc|error|warn|byte_get'"` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.35-o0-readelf | rg -i 'dynamic|hash|bucket|chain|symbol table|dynsym|\\.hash|gnu.hash|unable|read'"` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.35.2-o0-readelf | rg -C 8 'c8df0|c8e18|c8e40|c8d58|c9d79'"`

## CVE-2020-16593

readelf/nm 先查符号或导入模式 `scan_unit_for_symbols|strdup|lookup_var_by_offset|DWARF error: could not find variable specification; scan_unit_for_symbols|strdup|lookup_var_by_offset|DWARF error: could not find variable specification`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `12eb strdup; 1fd468 DWARF error: could not find variable specification at offset %lx; 1fd428 DWARF error: could not find variable specification at offset %lx`。随后 objdump+rg 用模式 `1fd428|1fd4|could not find variable; 1ff6a8|1ff6|could not find variable` 将锚点关联到地址簇 0x31459, 0x116261, 0x195400, 0x65719, 0x116087, 0x150141。据此把后续反汇编收敛到窗口 binutils-2.35.2-o0-objdump:0x15e190-0x15e290, binutils-2.35-o0-objdump:0x15c650-0x15c750, binutils-2.35.1-o0-objdump:0x15cb80-0x15cc80。

Windows: `binutils-2.35.2-o0-objdump:0x15e190-0x15e290`; `binutils-2.35-o0-objdump:0x15c650-0x15c750`; `binutils-2.35.1-o0-objdump:0x15cb80-0x15cc80`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.35-o0-objdump | rg 'scan_unit_for_symbols|strdup|lookup_var_by_offset|DWARF error: could not find variable specific...` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.35.1-o0-objdump | rg 'DWARF error: could not find variable specification|variable specification|strdup|DW_AT_specif...` | xref cmd: `/bin/zsh -lc "objdump -d binutils-2.35-o0-objdump | rg -n '1fd428|1fd4|could not find variable'"`

## CVE-2020-16599

readelf/nm 先查符号或导入模式 `strcmp|_bfd_elf_get_symbol_version_string; strcmp|_bfd_elf_get_symbol_version_string`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1de7bb   -v, --version            Display this program's version number; 1df646 version; 1e07bb   -v, --version            Display this program's version number`。随后 objdump+rg 用模式 `strcmp@plt; strcmp@plt` 将锚点关联到地址簇 0x314450, 0x140650, 0x1f6701, 0x140635, 0x317450, 0x141815。据此把后续反汇编收敛到窗口 binutils-2.35-o0-objdump:0x140000-0x1c0000, binutils-2.35.1-o0-objdump:0x140000-0x1c0000, binutils-2.35.2-o0-objdump:0x140000-0x1d0000, binutils-2.35-o0-objdump:0x10e650-0x10e7e5, binutils-2.35.1-o0-objdump:0x10e690-0x10e830。

Windows: `binutils-2.35-o0-objdump:0x140000-0x1c0000`; `binutils-2.35.1-o0-objdump:0x140000-0x1c0000`; `binutils-2.35.2-o0-objdump:0x140000-0x1d0000`; `binutils-2.35-o0-objdump:0x10e650-0x10e7e5`; `binutils-2.35.1-o0-objdump:0x10e690-0x10e830`; `binutils-2.35.2-o0-objdump:0x10fb40-0x10fce0`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.35.1-o0-objdump | rg 'strcmp|_bfd_elf_get_symbol_version_string'"` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.35-o0-objdump | rg '<corrupt>|Base|VER_NDX|gnu.version|version'"` | xref cmd: `/bin/zsh -lc "objdump -d -Mintel binutils-2.35.1-o0-objdump | rg -n -C 18 'strcmp@plt'"`

## CVE-2020-19724

readelf/nm 先查符号或导入模式 ` bfd_get_synthetic_symtab| bfd_canonicalize_dynamic_symtab| bfd_get_dynamic_symtab_upper_bound| bfd_read_mi...`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `136023 dynamic; 136119 synthetic; 13a023 dynamic`。未看到明确 objdump+rg 粗定位，模型直接进入局部窗口或停在符号/字符串级定位。没有显式 start/stop 局部窗口；定位结果主要是 objdump+rg 的上下文地址簇。

Trace: symbol/import cmd: `/bin/zsh -lc 'ls -l binutils-2.33.1-o0-nm binutils-2.33-o0-nm binutils-2.32-o0-nm binutils-2.34-o0-nm binutils-2.35-o0-nm binutils-2.35.1-o0-nm'` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.32-o0-nm | rg 'no symbols|dynamic|synthetic|invalid radix|no name'"`

## CVE-2020-35448

readelf/nm 先查符号或导入模式 `malloc|free|fprintf|printf|bfd|error|seek|read|memcmp|strlen`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1f8c98 %pB(%pA): relocation %d has invalid symbol index %ld; 1f98b0 %pB: warning: secondary relocation section '%s' for section %pA found - ignoring; 1faed8 %pB(%pA): relocation %d has invalid symbol index %ld`。随后 objdump+rg 用模式 `21e808|21e7c8|21e850|21e670|21d440` 将锚点关联到地址簇 0x123a23, 0x123a2a, 0x123a2d。据此把后续反汇编收敛到窗口 binutils-2.36.1-o0-objdump:0x13c560-0x13c850, binutils-2.35.1-o0-objdump:0x128420-0x128620, binutils-2.35.2-o0-objdump:0x1298c0-0x129ac8, binutils-2.36.1-o0-objdump:0x13c5e0-0x13c760。

Windows: `binutils-2.36.1-o0-objdump:0x13c560-0x13c850`; `binutils-2.35.1-o0-objdump:0x128420-0x128620`; `binutils-2.35.2-o0-objdump:0x1298c0-0x129ac8`; `binutils-2.36.1-o0-objdump:0x13c5e0-0x13c760`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -r binutils-2.35.1-o0-objdump | rg 'malloc|free|fprintf|printf|bfd|error|seek|read|memcmp|strlen'"` | strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.35.1-o0-objdump | rg 'secondary relocs|invalid symbol index|there is no howto|relocation %d|SHT_SECONDARY|secon...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel --no-show-raw-insn binutils-2.36.1-o0-objdump | rg '21e808|21e7c8|21e850|21e670|21d440' -C 5"`

## CVE-2021-20294

readelf/nm 先查符号或导入模式 `sprintf|strlen|printf; sprintf|strlen|printf`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `be406 @@%s; c69a4   [reserved (%d)]; c0406 @@%s`。随后 objdump+rg 用模式 `# (c040[6b]|c9bb[8e]); # (be40[6b]|c7bb[8e])` 将锚点关联到地址簇 0x170d6, 0x170dd, 0x170e0, 0x18136, 0x1813d, 0x18140。没有显式 start/stop 局部窗口；定位结果主要是 objdump+rg 的上下文地址簇。

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.35-o0-readelf | rg 'sprintf|strlen|printf'"` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.35-o0-readelf | rg '("'^| )(@@?%s| '"\\(%d\\))"'$|@@?%s| '"\\(%d\\)'"` | xref cmd: `/bin/zsh -lc "objdump -d binutils-2.35.2-o0-readelf | rg -C 14 '# (c040[6b]|c9bb[8e])'"`

## CVE-2021-45078

readelf/nm 先查符号或导入模式 `stab|debug_make|xcoff|fprintf|abort; "`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `1899904 debug_make_undefined_type: unsupported kind; 1902795 Unrecognized XCOFF type %d; 1119 ctime`。随后 objdump+rg 用模式 `21ca43; 21f343` 将锚点关联到地址簇 0xadd1b, 0xadd20, 0xadd24, 0xace51, 0xace56, 0xace5a。据此把后续反汇编收敛到窗口 binutils-2.37-o0-objdump:0xace30-0xace90, binutils-2.38-o0-objdump:0xae1f0-0xae250, binutils-2.35.2-o0-objdump:0xa8bf0-0xa8c60, binutils-2.40-o0-objdump:0xaeba0-0xaec10, binutils-2.36.1-o0-objdump:0xaa410-0xaa480。

Windows: `binutils-2.37-o0-objdump:0xace30-0xace90`; `binutils-2.38-o0-objdump:0xae1f0-0xae250`; `binutils-2.35.2-o0-objdump:0xa8bf0-0xa8c60`; `binutils-2.40-o0-objdump:0xaeba0-0xaec10`; `binutils-2.36.1-o0-objdump:0xaa410-0xaa480`; `binutils-2.39-o0-objdump:0xad320-0xad390`

Trace: symbol/import cmd: `/bin/zsh -lc "readelf -Ws binutils-2.37-o0-objdump | rg 'stab|debug_make|xcoff|fprintf|abort'"` | strings cmd: `/bin/zsh -lc "for f in binutils-2.*-o0-objdump; do printf '%s\\n' \""'$f"; strings -a -td "$f" | rg '"'Unrecognized XCOFF type|logical\\*8|integer\\*8|u...` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.38-o0-objdump | rg -C 90 '21ca43'"`

## CVE-2022-38533

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `23a600 %pB: warning: empty loadable segment detected at vaddr=%#lx, is this intentional?`。随后 objdump+rg 用模式 `23a600|empty loadable|vaddr` 将锚点关联到地址簇 0x219163, 0x23a600。据此把后续反汇编收敛到窗口 binutils-2.40-o0-objdump:0x13b000-0x13d500, binutils-2.42-o0-objdump:0x141000-0x143300, binutils-2.39-o0-objdump:0x138000-0x13a500, binutils-2.41-o0-objdump:0x140000-0x142300, binutils-2.37-o0-objdump:0x132700-0x133700。

Windows: `binutils-2.40-o0-objdump:0x13b000-0x13d500`; `binutils-2.42-o0-objdump:0x141000-0x143300`; `binutils-2.39-o0-objdump:0x138000-0x13a500`; `binutils-2.41-o0-objdump:0x140000-0x142300`; `binutils-2.37-o0-objdump:0x132700-0x133700`; `binutils-2.38-o0-objdump:0x138b00-0x139b00`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.40-o0-objdump | head -80'` | strings cmd: `/bin/zsh -lc "strings -a -tx binutils-2.40-o0-objdump | rg 'empty loadable segment detected|vaddr=%#'"` | xref cmd: `/bin/zsh -lc 'objdump -d --no-show-raw-insn binutils-2.40-o0-objdump | rg -n "23a600|empty loadable|vaddr"'`

## CVE-2022-48063

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `206e49 Section '%s' has an invalid size: %#llx.; 2235b8 %pB: invalid size field in group section header: %#lx; 20eea9 Section '%s' has an invalid size: %#llx.`。随后 objdump+rg 用模式 `20ff51|Section|ff 51|20ff; 21a111|Section|a1 11|21a1` 将锚点关联到地址簇 0x7b439, 0x7b43b, 0x7b442, 0x689a6, 0x689a9, 0x689ae。据此把后续反汇编收敛到窗口 binutils-2.39-o0-objdump:0x64c80-0x64e40, binutils-2.40-o0-objdump:0x66f00-0x670e0, binutils-2.39-o0-objdump:0x64c80-0x65040, binutils-2.40-o0-objdump:0x66f00-0x672c0, binutils-2.37-o0-objdump:0x66f80-0x67170。

Windows: `binutils-2.39-o0-objdump:0x64c80-0x64e40`; `binutils-2.40-o0-objdump:0x66f00-0x670e0`; `binutils-2.39-o0-objdump:0x64c80-0x65040`; `binutils-2.40-o0-objdump:0x66f00-0x672c0`; `binutils-2.37-o0-objdump:0x66f80-0x67170`; `binutils-2.41-o0-objdump:0x65f00-0x66170`

Trace: strings cmd: `/bin/zsh -lc "strings -tx binutils-2.37-o0-objdump | rg \"invalid size|has an invalid size|Section '%s'\""` | xref cmd: `/bin/zsh -lc 'objdump -d -Mintel binutils-2.39-o0-objdump | rg -C 8 "20ff51|Section|ff 51|20ff"'`

## CVE-2022-48064

readelf/nm 先查符号或导入模式 `strcmp|strncmp|bfd_get_section_by_name|bfd_get_section_by_name_if|strlen; strcmp|strncmp|bfd_get_section_by_name|bfd_get_section_by_name_if|strlen`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `20ffa7 .gnu.linkonce.wi.; 20ffb9 .debug_info; 21a167 .gnu.linkonce.wi.`。随后 objdump+rg 用模式 `20ffb9|20ffa7|21cb51|21cb5d|22fb07|22fcae|233317|233323; 21a179|21a167|226ed9|226ee5|239e37|239fde|23d557|23d563` 将锚点关联到地址簇 0x10412, 0x20ffa7, 0x10418, 0x10578, 0x21a167, 0x10584。据此把后续反汇编收敛到窗口 binutils-2.39-o0-objdump:0x65180-0x65420, binutils-2.40-o0-objdump:0x67450-0x67730, binutils-2.39-o0-objdump:0x128f80-0x129780, binutils-2.40-o0-objdump:0x12c900-0x12d120, binutils-2.39-o0-objdump:0x17fec0-0x180560。

Windows: `binutils-2.39-o0-objdump:0x65180-0x65420`; `binutils-2.40-o0-objdump:0x67450-0x67730`; `binutils-2.39-o0-objdump:0x128f80-0x129780`; `binutils-2.40-o0-objdump:0x12c900-0x12d120`; `binutils-2.39-o0-objdump:0x17fec0-0x180560`; `binutils-2.39-o0-objdump:0x194d00-0x195650`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.39-o0-objdump | head -40'` | strings cmd: `/bin/zsh -lc "strings -tx binutils-2.39-o0-objdump | rg '\\.debug_info|\\.zdebug_info|\\.gnu\\.linkonce\\.wi'"` | xref cmd: `/bin/zsh -lc "objdump -d -M intel binutils-2.39-o0-objdump | rg -n '20ffb9|20ffa7|21cb51|21cb5d|22fb07|22fcae|233317|233323'"`

## CVE-2022-48065

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `245948 DWARF error: can't find %s section.; 245970 DWARF error: section %s has no contents`。随后 objdump+rg 用模式 `"; "` 将锚点关联到地址簇 0x5f7cf, 0x5f7d0, 0x5f7d4, 0x175037, 0x17503b, 0x175042。据此把后续反汇编收敛到窗口 binutils-2.39-o0-objdump:0x174f70-0x175ed0, binutils-2.39-o0-objdump:0x17cf40-0x17d850, binutils-2.40-o0-objdump:0x1812a0-0x181bf0, binutils-2.38-o0-objdump:0x17c890-0x17d1b0, binutils-2.37-o0-objdump:0x174ff0-0x175900。

Windows: `binutils-2.39-o0-objdump:0x174f70-0x175ed0`; `binutils-2.39-o0-objdump:0x17cf40-0x17d850`; `binutils-2.40-o0-objdump:0x1812a0-0x181bf0`; `binutils-2.38-o0-objdump:0x17c890-0x17d1b0`; `binutils-2.37-o0-objdump:0x174ff0-0x175900`; `binutils-2.42-o0-objdump:0x187a60-0x189850`

Trace: strings cmd: `/bin/zsh -lc 'for f in binutils-2.{37,38,39,40,41,42}-o0-objdump; do echo "$(basename "$f")"; strings -a -t x "$f" | rg '"'abstract instance|variable sp...` | xref cmd: `/bin/zsh -lc 'for f in binutils-2.{37,38,39,40,41,42}-o0-objdump; do echo "$(basename "$f")"; objdump -T "$f" | rg '"' free| malloc| calloc| realloc| sp...`

## CVE-2023-1579

readelf/nm 确认动态符号/导入，如 `1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mkstemps@GLIBC_2.11 (2); 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)`；readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `2112d8 Cannot fetch indexed address: the .debug_addr section is missing; 211b30 DW_OP_addrx <0x%s>; 21b4f0 Cannot fetch indexed address: the .debug_addr section is missing`。随后 objdump+rg 用模式 `21b4f0|21bd50|258b9b|25b07b; 2112d8|211b30|24e85b|250d3b` 将锚点关联到地址簇 0x33d950, 0x16431, 0x21b4f0, 0x32e910, 0x16121, 0x2112d8。据此把后续反汇编收敛到窗口 binutils-2.41-o0-objdump:0x6e340-0x6e450, binutils-2.39-o0-objdump:0x6ae10-0x6af20, binutils-2.40-o0-objdump:0x6d2c0-0x6d3d0, binutils-2.42-o0-objdump:0x6eb20-0x6ec50, binutils-2.39-o0-objdump:0x1787e8-0x178940。

Windows: `binutils-2.41-o0-objdump:0x6e340-0x6e450`; `binutils-2.39-o0-objdump:0x6ae10-0x6af20`; `binutils-2.40-o0-objdump:0x6d2c0-0x6d3d0`; `binutils-2.42-o0-objdump:0x6eb20-0x6ec50`; `binutils-2.39-o0-objdump:0x1787e8-0x178940`; `binutils-2.40-o0-objdump:0x17cb0c-0x17cc70`

Trace: symbol/import cmd: `/bin/zsh -lc 'readelf -Ws binutils-2.40-o0-objdump | head -200'` | strings cmd: `/bin/zsh -lc 'strings -a binutils-2.40-o0-objdump | rg -n "debug_addr|dwarf_addr|addrx|debug_addr"'` | xref cmd: `/bin/zsh -lc 'objdump -d -Mintel binutils-2.40-o0-objdump | rg -n "21b4f0|21bd50|258b9b|25b07b" -C 8'`

## CVE-2023-25586

readelf -S 建立 .text/.rodata/.plt 地址坐标；strings 找字符串锚点 `225fd8 .gnu_debuglink; 227367 .gnu_debugaltlink; 227410   -Z, --decompress         Decompress section(s) before displaying their contents`。随后 objdump+rg 用模式 `NEEDED|RUNPATH|RPATH; 2353c0|2352a2|2352b7|bfd_init_section_decompress_status|compress\.c|ZLIB` 将锚点关联到地址簇 0x153937, 0x2352a2, 0x154078, 0x159371, 0x2458a8, 0x159512。据此把后续反汇编收敛到窗口 binutils-2.42-o0-objdump:0xfd000-0xfd5b0, binutils-2.40-o0-objdump:0xf7f00-0xf84a0, binutils-2.43-o0-objdump:0xfd900-0xfdeb0, binutils-2.41-o0-objdump:0xf7f00-0xf84a0, binutils-2.41-o0-objdump:0xf6d80-0xf6f90。

Windows: `binutils-2.42-o0-objdump:0xfd000-0xfd5b0`; `binutils-2.40-o0-objdump:0xf7f00-0xf84a0`; `binutils-2.43-o0-objdump:0xfd900-0xfdeb0`; `binutils-2.41-o0-objdump:0xf7f00-0xf84a0`; `binutils-2.41-o0-objdump:0xf6d80-0xf6f90`; `binutils-2.43-o0-objdump:0xfc740-0xfc950`

Trace: strings cmd: `/bin/zsh -lc "strings -a -t x binutils-2.40-o0-objdump | rg -i 'zstd|zlib|compress|decompress|gnu_debug|wrong format|unsupported compression'"` | xref cmd: `/bin/zsh -lc "readelf -d binutils-2.40-o0-objdump | rg 'NEEDED|RUNPATH|RPATH'"`
