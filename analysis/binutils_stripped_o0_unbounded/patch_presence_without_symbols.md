# Codex 如何在无源码符号表条件下判断 Patch Presence

来源材料：

- `analysis/binutils_stripped_o0_unbounded/address_localization_summary.{json,md}`
- `analysis/binutils_stripped_o0_unbounded/semantic_anchor_summary.{json,md}`
- `analysis/binutils_stripped_o0_unbounded/python_helper_usage.{json,md}`
- Raw 结果目录：`runs/binutils_stripped_o0_unbounded_raw`

本文总结 Codex 在 stripped `-O0` Binutils 二进制上，不依赖源码级符号表判断 patch presence 的方法，并记录本次 run 的统计结果。

## 总结

Codex 没有用版本号、源码路径或符号表里的函数名来判断补丁是否存在。该 run 的 prompt 明确要求只能使用本地二进制证据：字符串、动态导入、原始/反汇编指令、常量、分支、数据流、控制流和 guard 差异。

实际工作流可以概括为两步：

1. 用 stripped 后仍保留的语义锚点定位可疑代码区域。
2. 在局部指令层面，对照 patch intent 的行为清单判断 `present` 或 `absent`。

最主要的定位方式是 `.rodata` 语义锚点。95 个 CVE 中，有 86 个是先找到 patch 相关字符串、错误消息、section 名、format string 或 magic constant，再用这些地址在 `objdump` 输出里找 xref/callsite。最终判断不是“看到了某个字符串就算 patched”，而是继续检查附近指令是否实现了补丁要求的 guard、长度计算、错误路径、边界检查或是否仍保留漏洞侧行为。

这些 binary 是 stripped PIE executable，`srec_scan`、`parse_die` 这类源码函数名不能作为可靠锚点。动态导入和 PLT 名称，例如 `strlen@plt`、`strnlen@plt`、`sprintf@plt`、`qsort@plt`、`malloc@plt`、`free@plt`，有时可以作为 callsite 锚点，但它们本身不是最终证据。最终证据仍然是调用点周围的参数设置、分支条件和数据流。

## Codex 的判断方法

### 1. 先把源码补丁意图转成二进制检查清单

每个 CVE prompt 都给了压缩后的源码级信息：root cause、patch intent、behavior changes、patch hunk 和 reduced function code。Codex 先把这些信息转成可以在二进制里观察的行为清单。

例子：

- CVE-2014-8484：查找按 record type 计算 `min_bytes` 的逻辑、`bytes < min_bytes` 分支，以及在 buffer read 前触发 `"byte count %d too small"` 的错误路径。
- CVE-2017-15020：区分未加边界的 `strlen`/指针读取，和 patched 的 `xptr + N <= end` guard 以及带 remaining length 的 `strnlen`。
- CVE-2021-20294：区分漏洞侧的 `sprintf(buffer, "@%s", version_string)`，和 patched 的 `strlen(version_string) + 1` 长度计算，同时允许独立的 `" (%d)"` 整数格式化路径继续存在。

因此最终问题不是“这个二进制是不是某个版本”，而是“局部控制流/数据流是否实现了补丁要求的安全属性”。

### 2. 建立二进制地址坐标

Codex 通常先运行这些轻量命令：

- `file` 或 `ls`：确认文件是否存在，以及是否为 stripped ELF。
- `readelf -S`：确认 `.text`、`.rodata`、`.plt`、`.plt.sec`、`.got` 和 relocation section 的地址范围。
- `readelf -Ws` 或 `nm`：主要查看动态导入和 PLT 可用函数，而不是依赖 stripped 后不存在的内部函数名。

这些命令提供统一地址坐标。虽然目标是 PIE binary，但 `strings`、`readelf` 和 `objdump` 报出的静态虚拟地址可以互相对应，用来定位 xref 和局部窗口。

### 3. 找 stripped 后仍存在的语义锚点

大多数成功定位都从 `strings -a -t x` 开始，使用从 patch metadata 推导出的 CVE-specific pattern。

常见锚点包括：

- 错误字符串：`"byte count %d too small"`、`"invalid size field in group section header"`、`"Dwarf Error: Line info data is bigger"`。
- Format string：`"@%s"`、`" (%d)"`、`"%B: corrupt ..."`。
- Section 名和 magic string：`.gnu_debuglink`、`.plt`、`.plt.got`、`.debug_info`、`.gnu.version_r`、`!<thin>`、`/SYM64/`。
- 领域相关字符串：DWARF、S-record、archive、relocation、compression、GNU property、XCOFF、PE/COFF。

找到 rodata 地址后，Codex 再在反汇编里搜索这些地址：

```text
strings -a -t x ... | rg 'patch-relevant-pattern'
objdump -d -M intel ... | rg 'rodata-address-1|rodata-address-2' -C N
objdump -d -M intel --start-address=... --stop-address=...
```

xref 通常表现为 RIP-relative `lea` 指令。即使没有内部函数名，这些 xref 也能给出足够精确的代码邻域。

### 4. 字符串不够强时，用导入函数和 callsite pattern

有些 CVE 附近没有足够独特的 rodata 字符串。Codex 就改用调用点级别的锚点：

- `strnlen@plt` 与 `strlen@plt`：用于识别 bounded string parsing fix。
- `sprintf@plt` 的调用形态和参数设置：用于 CVE-2021-20294。
- `qsort@plt` 及其周围 synthetic symbol table 逻辑。
- `malloc`、`free`、类似 `bfd_malloc` 的 wrapper，以及 cleanup 路径中的释放次数。
- DWARF block-length parsing 里的间接 getter call 和指针运算。

这仍然不依赖源码符号。导入函数名来自动态链接，真正决定状态的是调用点附近的寄存器/栈参数、比较、跳转和指针更新。

### 5. 比较局部控制流和数据流，而不是整函数

定位后，Codex 会把反汇编收敛到局部窗口，只看 patch-relevant basic blocks。

`present` 的常见证据：

- 在读取或指针推进前新增 compare 和条件分支。
- 新增失败路径，例如返回 `0`、设置 `bfd_error_bad_value` 或跳到 `error_return`。
- `strnlen` 使用剩余 buffer/section 长度作为边界。
- 使用 `strlen(version_string) + 1` 做长度 accounting，而不是把 `version_string` 写进 stack buffer。
- allocation size 或循环边界来自已验证的值。

`absent` 的常见证据：

- 漏洞侧读取或指针推进发生在任何 end check 之前。
- 仍保留 unbounded `strlen` 或 `sprintf("@%s")`。
- patch 引入的 branch、guard 或字符串在局部块中不存在。
- 代码直接从 attacker-controlled length 进入 allocation/read/parse。

### 6. 跨版本对齐只是 sanity check，不是判定依据

Codex 经常检查同一个语义块在多个 requested binaries 中的形态。例如，一个 binary 显示漏洞侧 unchecked flow，另一个 binary 显示新增 guard 和错误路径。这个对比有助于确认代码区域和解释指令语义，但最终状态仍然必须引用每个 binary 自己的本地证据。

### 7. Python helper 使用较少，且用途明确

Python 主要用于 grep/objdump 不够方便的场景，例如扫描大量反汇编、十进制地址转 hex、按 prologue/endbr 分组近似函数块、识别重复指令模式。Python 不是主方法；本次 95 个 CVE 里只有 15 个使用了 Python helper。

## 具体例子

### CVE-2014-8484：新增错误字符串加控制流验证

Patch intent：拒绝 byte count 小于 record-type 最小长度的 S-record。

Codex 先找到 `"Bad checksum in S-record file"` 和 `"byte count %d too small"` 等 rodata 字符串，再把字符串地址 xref 到 S-record parsing block。

最终证据：

- `binutils-2.24-objdump` 判为 `absent`：`"byte count %d too small"` 字符串不存在；byte-count 计算后直接进入 `bytes * 2` buffer sizing 和 read compare，没有 `min_bytes` 计算和 `bytes < min_bytes` 分支。
- `binutils-2.25`、`2.25.1`、`2.26` 判为 `present`：局部块把 `min_bytes` 初始化为 3，对 record type `2/8` 改成 4，对 `3/7` 改成 5，然后比较 `bytes` 和 `min_bytes`，失败时进入 patched error path，且发生在后续 read 之前。

这是典型的“字符串锚点定位 + 指令级 guard 验证”。

### CVE-2017-15020：用导入/callsite 和边界语义判断

Patch intent：给 DWARF parsing read 加边界检查，并把不安全字符串扫描替换成 bounded length check。

Codex 使用 `strnlen@plt`/`strlen@plt`、pointer-end compare 和 parse loop 结构作为锚点。

最终证据：

- `binutils-2.29-objdump` 判为 `absent`：parse-like routine 在没有 `xptr + N <= end` 检查的情况下读取 length 和 attribute，并调用 `strlen@plt` 后推进指针。
- `binutils-2.30`、`2.31`、`2.31.1` 判为 `present`：局部代码在读取前检查 `xptr+4`、`xptr+2` 和后续 block advance 是否越过 end；字符串处理计算 remaining length 并调用 `strnlen@plt`。

注意，这不是“看到 `strnlen` 就算 patched”。证据还包含参数设置和周围 guard。

### CVE-2021-20294：区分类似 format string 的不同用途

Patch intent：停止使用 `sprintf(buffer, "@%s", version_string)` 做长度 accounting，改用 `strlen(version_string) + 1`，同时保留 `" (%d)"` 的整数格式化。

Codex 通过 `"@@%s"`、`"@%s"` 和 `" (%d)"` 等字符串定位，再检查 callsite 参数和数据流。

最终证据：

- `binutils-2.35` 和 `2.35.1` 判为 `absent`：局部块把 `version_string` 放到参数寄存器，把 stack buffer 作为 destination，选择 `"@%s"` format，调用 `sprintf@plt`，再把返回值从 available length 中减掉。
- `binutils-2.35.2` 和 `2.36.1` 判为 `present`：局部块对 `version_string` 调用 `strlen@plt`，减去长度再减 1；`sprintf` 只用于独立的 `" (%d)"` 整数路径。

这说明 Codex 检查的是参数和数据流，不只是 grep `sprintf` 或 format string。

### CVE-2018-7568：没有强字符串时直接看控制流

Patch intent：给 `FORM_BLOCK2` 和 `FORM_BLOCK4` 的 length-based pointer advance 加 guard。

Codex 使用 parse-like call pattern 和指令结构定位，然后比较 block-length handling。

最终证据：

- `binutils-2.30-objdump` 判为 `absent`：`FORM_BLOCK2` 和 `FORM_BLOCK4` 读取长度后立即推进指针，没有 end check。
- `binutils-2.31`、`2.31.1`、`2.32` 判为 `present`：两个 block 都先保存长度，计算 `xptr + block_len`，和 DIE end pointer 比较，越界时先返回 false，再决定是否推进指针。

这是 rodata 不够决定性时，依靠 import/callsite 或裸控制流判断的代表。

## 本次 Run 统计

### 覆盖范围和最终结果

| 指标 | 数值 |
|---|---:|
| 有 raw prompt/stdout/stderr/timing 文件的 CVE | 95 |
| 有 `last.json` 最终结构化结果的 CVE | 93 |
| 失败/无最终结构化结果 | 2 |
| 有效 `last.json` 中的 binary-level 判定 | 399 |
| 每个成功 CVE 的 requested binaries，min/median/mean/max | 4 / 4 / 4.29 / 6 |

失败/无最终结构化结果：

- `CVE-2017-13757`：多次 reconnect 后 stream disconnected before completion。
- `CVE-2017-14974`：remote compaction 失败，返回 `502 Bad Gateway`，没有生成有效 `last.json`。

399 个 binary-level 判定的状态分布：

| 状态 | 数量 |
|---|---:|
| `present` | 260 |
| `absent` | 111 |
| `not_found` | 22 |
| `inconclusive` | 6 |

置信度分布：

| 置信度 | 数量 |
|---|---:|
| `high` | 391 |
| `medium` | 7 |
| `low` | 1 |

状态和置信度交叉统计：

| 状态 / 置信度 | 数量 |
|---|---:|
| `present/high` | 260 |
| `absent/high` | 109 |
| `not_found/high` | 22 |
| `inconclusive/medium` | 5 |
| `absent/medium` | 2 |
| `inconclusive/low` | 1 |

### 语义锚点统计

| Anchor Type | CVE 数 |
|---|---:|
| `string_rodata_xref` | 86 |
| `string_anchor_window_no_xref` | 4 |
| `string_anchor_no_explicit_window` | 3 |
| `import_or_callsite_anchor` | 2 |

地址定位事件统计：

| 指标 | 数值 |
|---|---:|
| 解析到的 command/localization events | 2403 |
| 平均每个 CVE 的 events | 25.29 |
| trace 中有 string anchors 的 CVE | 93 |
| trace 中有 grep/xref anchors 的 CVE | 88 |
| 做过 section-coordinate setup 的 CVE | 87 |
| 做过 symbol/import probing 的 CVE | 72 |

局部 objdump 窗口统计：

| 指标 | 数值 |
|---|---:|
| 显式 local windows 总数 | 526 |
| 有显式 local windows 的 CVE | 86 |
| 没有显式 local windows 的 CVE | 9 |
| 平均每个 CVE 的 windows | 5.54 |
| 单个 CVE 最大 windows 数 | 8 |

解析 trace 中没有显式 `--start-address/--stop-address` local windows 的 CVE：

- `CVE-2017-14940`
- `CVE-2017-15996`
- `CVE-2017-16828`
- `CVE-2017-9039`
- `CVE-2017-9040`
- `CVE-2018-10372`
- `CVE-2018-20002`
- `CVE-2020-19724`
- `CVE-2021-20294`

### 命令和耗时统计

| 指标 | 数值 |
|---|---:|
| Timing files | 95 |
| Codex exec return code `0` | 93 |
| Codex exec return code `1` | 2 |
| 总 wall time | 28,532.89 s |
| 平均每个 CVE wall time | 300.35 s |
| 中位数 wall time | 235.18 s |
| 最短 wall time | 91.80 s |
| 最长 wall time | 1,121.54 s |
| 已记录 completed turns | 93 |

completed turns 的 token 使用：

| Token 指标 | 数量 |
|---|---:|
| Input tokens | 48,440,194 |
| Cached input tokens | 35,903,104 |
| Output tokens | 1,109,061 |
| Reasoning output tokens | 691,837 |

命令执行统计：

| 指标 | 数值 |
|---|---:|
| 解析到的 command executions | 2403 |
| Command exit code `0` | 2319 |
| Command exit code `1` | 67 |
| Command exit code `2` | 17 |
| 命令总运行时间 | 183.60 s |
| 命令平均运行时间 | 0.076 s |
| 命令运行时间中位数 | 0.00015 s |
| 命令总输出 | 45,981,239 bytes |
| 命令平均输出 | 19,135 bytes |

命令类别是重叠统计，因为同一条命令可能同时包含 `objdump` 和 `rg`。

| 类别 | 数量 |
|---|---:|
| `objdump` | 2235 |
| `rg` | 1363 |
| `readelf` | 630 |
| `strings` | 406 |
| `file` | 142 |
| `ls` | 89 |
| `nm` | 49 |
| `python3` | 41 |
| `xxd` | 8 |
| `other` | 7 |

耗时最长的 CVE：

| CVE | Wall Time | Return Code |
|---|---:|---:|
| `CVE-2017-14930` | 1,121.54 s | 0 |
| `CVE-2018-20651` | 978.90 s | 0 |
| `CVE-2017-8392` | 868.16 s | 0 |
| `CVE-2017-14974` | 692.69 s | 1 |
| `CVE-2018-8945` | 667.87 s | 0 |

### Python Helper 使用统计

| 指标 | 数值 |
|---|---:|
| 使用任意 Python helper 的 CVE | 15 |
| 完成的 Python helper commands | 41 |

| Helper Kind | Commands | CVEs |
|---|---:|---:|
| `objdump_scan` | 18 | 8 |
| `addr_convert` | 16 | 7 |
| `file_or_json_helper` | 5 | 3 |
| `other_python_helper` | 2 | 2 |

## 结论

Codex 的有效策略不是符号恢复，而是“语义定位 + patch intent 验证”：

- 源码补丁描述安全属性。
- 字符串、rodata 常量、导入函数和 section 坐标把搜索范围缩小到少量代码窗口。
- 局部指令行为决定最终状态。
- 只有看到 patched guard/data-flow，才判 `present`。
- 只有看到漏洞侧机制，才判 `absent`。
- binary 存在但两边证据都不充分时，正确结果是 `inconclusive`。

本次 stripped `-O0` Binutils run 表明，这套方法可以稳定工作：95 个 CVE 中 93 个产出结构化最终 JSON，生成 399 个 binary-level 判定，其中 391 个为 high confidence。主要失败模式是两个长 run 的基础设施/输出失败，而不是 stripped code 无法定位。
