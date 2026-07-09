# pptagent Architecture and Tools

Source documents:

- `/home/zhangxb/ClawSpace/codex/pptagent/ARCHITECTURE.md`
- `/home/zhangxb/ClawSpace/codex/pptagent/tools.md`

---

# pptagent Architecture

`pptagent` is a **model-driven binary patch-presence harness**. Given one
project, one CVE, and one stripped binary, a DeepSeek model decides a verdict —
`present` / `absent` / `not_affected` / `inconclusive` — using only bounded,
read-only `binutils` observations of that binary. The harness's job is to keep
the model **grounded**: it executes the tools the model asks for, mints typed
observations + an evidence ledger, and refuses any verdict that is not backed by
real evidence ids.

The design splits the LLM's work into two cooperating roles plus one pre-filter:

| Role | LLM use | Module | Responsibility |
|------|---------|--------|----------------|
| **Pre-gate triage** | LLM #1 (optional) | `core/pregate.py` | Cheap applicability short-circuit *before* the main loop. The model names applicability checks; the harness **independently re-verifies** them against real binary facts before trusting a `not_affected`. |
| **Detector agent** | LLM #2 (core loop) | `core/agent_loop.py` | The bounded tool loop. The model picks tools, reads observations/evidence, and **proposes** a verdict via `submit_detection_result`. |
| **Validator agent** | LLM #3 (optional) | `core/validators/` | Audits the proposed verdict before it is accepted. Deterministic layers always run; an LLM auditor runs in `llm`/`both` mode. Failures **repair** (sent back to the detector), never crash. |

> **One sentence on the LLM's role:** the LLM is the *decision-maker* (which
> tool to run, how to read the disassembly, what the verdict is) and the
> *adversarial auditor* (does the cited evidence really support the verdict),
> while the harness is the *bounded executor, ledger, and gate* — **the model
> proposes, deterministic checks dispose.**

## Layered module map

```
core/
  agent_loop.py      # DETECTOR: build prompt → sample model → dispatch tools → finalize
  pregate.py         # PRE-GATE: LLM applicability triage, machine-verified
  model_client.py    # DeepSeek OpenAI-compatible chat call (shared by all 3 LLM touchpoints)
  observations.py    # typed observations + evidence-ledger compaction for the model
  runtime.py         # AGENT_CONTEXT global state, metric + evidence recording
  prompting.py       # task prompt + finalization nudges
  schema_utils.py    # JSON-schema load/validate
  final_result.py    # finalization: assemble candidate → run validator stack → accept/repair
  validators/        # VALIDATOR stack
    protocol.py        #   structural/schema gate (deterministic)
    regex_semantic.py  #   citation-coherence / polarity / evidence-id audits (deterministic)
    llm_semantic.py    #   LLM second-opinion auditor (optional)
tools/               # TOOL-CALL layer (binutils-backed; see tools.md)
  anchors.py, disassembly.py, structures.py, allocation.py,
  applicability.py, generic.py, asm.py, elf.py, shared.py, flows/
evaluation/          # BATCH layer: case building, per-case subprocess, metrics
host.py              # host preflight, env loading, subprocess command execution
command_policy.py    # default-deny allowlist + path confinement
tools_registry.py    # tool name → implementation map
```

See `tools.md` for the full tool ↔ command-line and evidence-kind tables.

## End-to-end flow

<p align="center">
  <img src="docs/architecture_new.svg" alt="pptagent architecture flow" width="100%">
</p>

<p align="center">
  <sub>
    Vector <a href="docs/architecture_new.svg">SVG</a> ·
    high-res <a href="docs/architecture_new.png">PNG</a> ·
    print <a href="docs/architecture_new.pdf">PDF</a>.
    Source is the hand-authored <a href="docs/architecture_new.svg"><code>architecture_new.svg</code></a>;
    re-render PNG/PDF with <code>docs/_render.html</code> via headless Chrome.
  </sub>
</p>

> LLM steps are highlighted in amber. Everything else (preflight, factsheet
> probes, tool execution, observation/evidence minting, the protocol + regex
> gates) is deterministic harness code.

## 各阶段详细说明（Stage-by-stage）

下面按流程图从左到右、从上到下逐阶段说明。**琥珀色节点是 LLM 决策点**,其余都是确定性 harness 代码。每个阶段都标注了对应代码位置,便于对照实现。

### 阶段 0 · 输入与主机预检（Input & preflight）

- **目的**:把"一个 case"准备成模型可消费的有界输入,并采集二进制的客观身份信息。
- **输入**:一个三元组 —— `project` + `CVE` + 一个 **stripped 二进制**;外加该 CVE 的 metadata(行为/补丁信息)。
- **步骤**:
  1. `host.preflight_detection_inputs` 跑主机预检:确认二进制存在、计算 `sha256`、读 ELF 头(`readelf -h` / `file`)、用 `nm` 给出 *symbol hint*(判断是否有可锚定的函数符号)。
  2. `host.load_cve_metadata` 载入 CVE metadata;`prompting.build_task` 把 metadata + 预检结果拼成 task JSON。
- **LLM 作用**:无。这一阶段纯确定性,只为后续 LLM 提供**有界事实**。
- **去向**:进入 `pregate?` 分支 —— 启用则走 **阶段 1**,否则直接进 **阶段 2**。
- **代码**:`host.py`、`core/prompting.py:build_task`、`core/agent_loop.py:run_agent`(预检调度)。

### 阶段 1 · PRE-GATE 预检闸（LLM #1,可选,`core/pregate.py`)

- **目的**:在昂贵的主循环之前,用一次廉价的 LLM 调用尝试**短路判定** —— 主要是判断"这个二进制根本不在该 CVE 的影响范围内"(`not_affected`),例如某可选 backend 没编进来、或平台位宽不符。
- **关键设计:提议-复核(propose-then-verify)**。LLM 只负责*命名要检查什么*,**不允许**它的话直接成为结论。
- **步骤**:
  1. `collect_applicability_facts` + `render_factsheet`:harness 先用 `readelf` / `nm` / `strings` 采一份"适用性事实表"(NEEDED 库、动态符号、关键字符串)。
  2. `run_triage` → LLM:模型读事实表,**点名**一组适用性检查(例如"若不存在 `libssh2` 这个 NEEDED 库则该特性未编入"),并可提议 `not_affected`。
  3. `_verify_and_build`:harness **独立地**拿真实二进制重新核对模型点名的库/符号前缀。**只有核对通过**才铸造平台/特性证据(`binary_platform_profile` / `target_feature_path_absent` 等)并接受短路;核对不过则丢弃模型的短路提议。
- **LLM 作用**:*假设生成器* —— 提出"该查哪些适用性条件",但其主张被机器复核裁决。
- **去向**:
  - 复核通过的短路 → 直接产出 `not_affected`,跳到 **阶段 4**(绿色 `not_affected` 边)。
  - 未短路 → 落到 **阶段 2** 主循环(`no` 边)。
- **代码**:`core/pregate.py:{collect_applicability_facts, run_triage, _verify_and_build, maybe_run_pregate}`。

### 阶段 2 · DETECTOR 检测主循环（LLM #2,核心,`core/agent_loop.py`)

- **目的**:这是系统的**核心**。模型在有界、只读的工具循环里反复观察二进制,形成假设,最终通过 `submit_detection_result` **提议**一个判定。
- **循环单步**:
  1. **LLM 选工具**(琥珀节点):模型根据 system prompt + task + 已有观测,决定下一个工具调用(读反汇编、查字符串、做 xref 定位等,见 `tools.md`)。
  2. **harness 执行**:经 `command_policy.validate_command` 闸门(默认拒绝白名单 + 路径限定到唯一目标二进制)后运行该 binutils 工具,铸造一条 typed observation(`obs_XXXX`)+ 一条或多条证据账本项(`ev_XXXX`)。
  3. **结果回灌**:`observations.compact_tool_result_for_model` 把结果压缩后喂回模型(蓝色虚线 *fed back*),进入下一轮。
- **三个有界阶段**(防止无限循环 / 强制收敛):
  - **explore**(`--max-turns`,默认较大):自由探索 + 调工具。
  - **finalize-nudge**(`--finalization-turns`):达到上限后,prompt 提醒模型"该交卷了"。
  - **forced repair**(≤2):若仍未交出合法判定,只暴露 `submit_detection_result` 一个工具,强制其用既有证据交卷(证据不足就交 `inconclusive`)。
- **LLM 作用**:*决策者* —— 决定看哪里、如何解读反汇编、最终判定是什么。harness 只是有界执行器 + 证据账本。
- **去向**:模型调用 `submit_detection_result` 时(`submit? = yes`)→ `finalize`(候选清洗)→ **阶段 3**。
- **判定取值**:`present` / `absent` / `not_affected` / `inconclusive`。**确定性判定**(前三者)必须引用真实的 `ev_XXXX`。
- **代码**:`core/agent_loop.py:{run_agent, handle_tool_calls}`、`core/observations.py`、`tools/`、`command_policy.py`。

### 阶段 3 · VALIDATOR 校验闸（LLM #3,`core/validators/`)

- **目的**:在判定被**正式接受之前**做对抗式审计。任何一层不通过都不是崩溃,而是把错误打包成 *repair payload* 退回 **阶段 2** 让模型修。
- **校验栈(`final_result.validate_final_tool_args` 顺序串联)**:
  1. **protocol**(确定性,`validators/protocol.py`):JSON-schema + 结构闸 —— 字段齐全、枚举合法、证据 id 形态正确。
  2. **regex_semantic**(确定性,`validators/regex_semantic.py`):语义审计 —— 证据 id 真实性闸、引用一致性(reasoning 与所引证据是否对得上)、极性检查、NPD 类必须有 null-flow 证据、特性门控的负向判定检查、版本/路径不可采信项剔除。
  3. **llm_semantic**(LLM,可选,`validators/llm_semantic.py`):仅在 `--semantic-validator llm`/`both` 模式启用 —— 第二个模型读"判定 + 被引证据",独立判断**证据是否真的支撑该结论**。
- **LLM 作用**:*对抗式审计者* —— 给检测结果一个独立的第二意见。可用 `--validator-model` 指定比 detector **更强的模型**来审更便宜的 detector。
- **去向**:
  - 全部通过(`pass? = yes`)→ **阶段 4**(绿色 `accepted` 边)。
  - 任一不过 → 红色 `repair payload` 边回到 **阶段 2** 的 LLM,继续修(受 forced-repair 上限约束)。
- **代码**:`core/final_result.py:{validate_final_tool_args, submit_detection_result}`、`core/validators/{protocol,regex_semantic,llm_semantic}.py`。

### 阶段 4 · 输出（`final_result.json`)

- **目的**:落盘被接受的最终结论及全部可复核材料。
- **产出**:`final_result.json` 含 —— 判定 `status` + `confidence`、被引用的 `evidence_ids`、`decisive_addresses`(人工复核锚点)、`reasoning`、完整的 `observations` 与 `evidence_ledger`、`harness_metrics`(轮数、repair 次数等)、`usage_metrics`(token 用量)。同时写 `transcript.json`。
- **三种到达方式**:阶段 1 的复核短路(`not_affected`)、阶段 3 通过(`accepted`)、或主循环用尽后强制交出的 `inconclusive`。
- **代码**:`core/final_result.py:{build_final_artifact, write_run_outputs}`。

## How the LLM is kept grounded

The harness is built so the model can be *creative in where it looks* but
*cannot fabricate conclusions*:

1. **Bounded inputs.** The model sees only the CVE-metadata prompt, the target
   binary, and `binutils` observations derived from it. Debug/source/DWARF
   signals are blocked at `command_policy` (default-deny allowlist + path
   confinement to the one target binary).
2. **The observation is the citable evidence.** Every successful tool call mints
   a typed observation (`obs_XXXX`) and one+ ledger items (`ev_XXXX`). A
   determinate verdict (`present`/`absent`/`not_affected`) **must** cite real
   `ev_XXXX` ids — free-text-only evidence is rejected (`runtime.py` +
   `validators/regex_semantic.py`).
3. **Propose-then-verify in the pre-gate.** The triage LLM only *names* the
   applicability checks; `pregate._verify_and_build` re-runs them against the
   real binary and mints the evidence itself. An unverified short-circuit is
   discarded.
4. **Adversarial validation on finalize.** The proposed verdict passes a
   protocol gate, a deterministic semantic auditor, and (optionally) an
   independent LLM auditor. Any failure becomes a **repair payload** returned to
   the detector loop — the run continues instead of crashing.
5. **Phased termination.** The detector loop runs explore → finalize-nudge →
   forced-repair phases (`--max-turns`, `--finalization-turns`, ≤2 repairs).
   Only model-API failures (after retries) abort; tool/schema failures repair
   in-band.

## The three LLM touchpoints at a glance

| # | Where | Prompted to… | Harness check on its output |
|---|-------|--------------|------------------------------|
| 1 | `pregate.run_triage` | Name applicability checks; optionally short-circuit to `not_affected`. | `_verify_and_build` independently re-checks claimed libs/symbols against the binary before accepting. |
| 2 | `agent_loop.run_agent` | Choose tool calls, interpret observations, decide and submit the verdict. | Tools are policy-gated; the submitted verdict must pass the validator stack. |
| 3 | `validators.llm_semantic.validate_llm_semantic` | Audit whether the cited evidence actually supports the proposed verdict. | Runs only in `llm`/`both` mode; its errors trigger a repair, not acceptance. |

All three share one model client (`core/model_client.py`, DeepSeek
OpenAI-compatible, default flash/non-thinking). The detector and validator can
use **different models** (`--validator-model`) so a stronger model can audit a
cheaper detector.

---

# pptagent Tools & Evidence Reference

This document maps the model-callable **tools** to the actual command-line
programs they execute, and catalogs every **evidence kind** the harness mints
into the evidence ledger. Each table also names the **fix-pattern / vulnerability
trace** the tool or evidence is meant to surface — i.e. what kind of patch shape
it helps prove present or absent. It is generated from the live code under
`tools/`, `core/`, and `host.py` — keep it in sync when tools or evidence kinds
change.

All tools are bounded, read-only, and confined to the single target binary by
`command_policy.validate_command` (default-deny allowlist + path confinement).
`objdump -d` is rendered as `objdump -d -Mintel <binary>` when `syntax="intel"`,
otherwise AT&T. Every successful tool call mints one typed observation
(`obs_XXXX`) plus one or more evidence-ledger items (`ev_XXXX`); the model cites
those ids in its final verdict.

## Tools → category, fix-pattern target & underlying command-line tools

| Tool | Category | What it does | Fix-pattern / vuln trace it targets | Actual CLI command(s) |
|------|----------|--------------|--------------------------------------|------------------------|
| `run_command` | Generic / shell | Runs one policy-gated read-only command and mints a typed observation. The general-purpose escape hatch for inspection/filtering. | Any patch shape not covered by a specialized probe — raw binutils output for ad-hoc patterns. | Any allowlisted `binutils` / filter command (`objdump`, `readelf`, `strings`, `nm`, `file`, `grep`, `head`, …), validated by `validate_command` |
| `strings_grep` | String / rodata anchor | Lists string literals with file offsets, returns only regex-matching lines. | Patches anchored by string literals — new/changed error messages, format strings, option names, protocol tokens, headers. | `strings -a -tx <binary>` (+ in-process regex filter) |
| `string_xrefs` | String / rodata anchor | Maps matching strings → ELF virtual addresses → bounded disassembly windows that reference them. Locates rodata-anchored code in stripped binaries. | String-anchored fixes — locates the patched function via a format/error/option string it references. | `strings -a -tx <binary>` · `readelf -W -S <binary>` · `objdump -d [-Mintel] <binary>` |
| `symbol_xrefs` | Symbol / import anchor | Finds matching dynamic symbols / relocations / PLT labels, returns disassembly windows referencing their addresses. For imports called via GOT/function pointer. | Memory-safety fixes with no string anchor — locates an unsymboled static function via a libc/import it calls (added guard/bounds check before a call). | `readelf -W -s <binary>` · `readelf -W -r <binary>` · `objdump -d [-Mintel] <binary>` |
| `objdump_grep` | Disassembly read | Disassembles the whole binary and returns bounded context windows around regex matches. | Specific instruction shapes anywhere — overflow/bounds guard (`cmp`+`ja/jae`), a return-code (`mov eax,<imm>`), a changed/added call. | `objdump -d [-Mintel] <binary>` (+ in-process regex) |
| `objdump_window` | Disassembly read | Returns a bounded disassembly window (between start/stop addresses) of the target. | Reading the exact fix shape at a known site — added guard, bounds check, new field assignment, bounded vs. unbounded call. | `objdump -d [-Mintel] <binary>` |
| `null_guard_flow` | NULL-guard flow | Summarizes whether a tracked pointer register/stack slot has local NULL compare/test guards before dereference or sink use-sites. Supports `pointer_target=AUTO` to rank candidate pointers near sink lines when the vulnerable target is unclear. | CWE-476 / NPD fixes — added `ptr == NULL` checks before dereference, byte copy, string conversion, parser calls, or memcpy-like sinks. | `objdump -d [-Mintel] <binary>` (windowed) |
| `struct_accesses` | Struct / field flow | Summarizes base+offset struct-like reads/writes and nearby field-copy pairs from a bounded window. | Struct field init/propagation/copy fixes — added field assignment, missing initialization, a field carried across a copy. | `objdump -d [-Mintel] <binary>` (windowed) |
| `struct_copy_search` | Struct / field flow | Scans the full disassembly for clusters of struct-like field-copy pairs; returns compact candidate ranges when the function address is unknown. | Field-copy / propagation fixes when the function address is unknown — a patch that copies/propagates struct fields. | `objdump -d [-Mintel] <binary>` (full) |
| `allocation_size_flow_search` | Allocation flow | Searches allocator call-site windows for size arithmetic, overflow guards, and limit constants. | Integer-overflow-before-allocation fixes — added overflow guard / size-arithmetic change / limit constant before `malloc`/`calloc`/`realloc`. | `readelf -W -s <binary>` · `readelf -W -r <binary>` · `objdump -d [-Mintel] <binary>` |
| `platform_applicability_scan` | Applicability (`not_affected`) | Reads ELF class/machine/inferred `size_t` width and compares against a metadata 32/64-bit / ILP32 precondition. | Architecture / word-size scoped CVEs — 32-bit-only / ILP32 `size_t` overflow; decides `not_affected` by platform. | `readelf -h <binary>` (LC_ALL=C) · `file <binary>` (via `binary_platform_profile`) |
| `feature_applicability_scan` | Applicability (`not_affected`) | Checks NEEDED libraries, dynamic symbols, and strings for an optional feature/backend marker; flags a feature path not compiled/linked in. | Optional-feature / backend scoped CVEs — vuln in a backend/dependency not compiled or linked in; decides `not_affected` by feature path. | `readelf -d <binary>` · `readelf -W -s <binary>` · `strings -a <binary>` |
| `submit_detection_result` | Finalization | Submits the final verdict (`present` / `absent` / `not_affected` / `inconclusive`) with cited evidence ids. Called exactly once; runs no CLI. | — (finalization, not a search probe) | — (in-process schema + evidence-id gate) |

## Evidence kinds

Polarity: **positive** = evidence the searched-for shape/anchor was found;
**negative** = evidence that an expected anchor/match was *absent* (used to bound
the search and support `absent` / `not_affected` / `inconclusive`).

| Evidence kind | Minted by | Polarity | Fix-pattern / vuln trace it evidences | Meaning |
|---------------|-----------|----------|---------------------------------------|---------|
| `command_output` | `run_command` (`core/observations.py`) | positive | Any ad-hoc patch shape — raw command excerpt. | Stdout excerpt of a generic policy-gated command. |
| `no_pipeline_match` | `run_command` | negative | Absence of an expected textual marker. | A shell pipeline / filter returned no matching lines. |
| `file_summary` | generic observation | positive | Build/platform identity (context, not a fix shape). | `file` output summary of the target binary. |
| `symbol_sample` | generic observation | positive | Symbol availability — whether named functions can anchor a search. | Sampled defined text symbols (from `nm`). |
| `dynamic_libraries` | generic observation | positive | Linked-dependency presence — backend/feature applicability. | Dynamic / `NEEDED` library list extract. |
| `needed_libraries_complete` | generic obs · `feature_applicability_scan` | positive | Feature/backend `not_affected` — a backend absent from the *complete* NEEDED list. | The complete `NEEDED` library list (complete-list semantics). |
| `elf_sections` | generic observation | positive | Address-mapping support for string/symbol xrefs. | `readelf -S` section table extract. |
| `strings_match` | `strings_grep` | positive | String-anchored fix — presence of a new/changed message/format/option. | String literal(s) matching the regex, with file offsets. |
| `no_string_match` | `strings_grep` | negative | Absent string anchor — message/option/feature path not present. | No string literal matched the regex. |
| `string_anchor` | `string_xrefs` | positive | String-anchored localization — string mapped to its code address. | Matching string mapped to its ELF virtual address. |
| `string_xref_window` | `string_xrefs` | positive | Fix shape near a referenced string — patched code at a rodata-anchored site. | Disassembly window referencing a string's address. |
| `no_string_xref_anchor` | `string_xrefs` | negative | String-anchored localization failed — no rodata anchor/xref. | No rodata anchor / xref found for the string regex. |
| `symbol_anchor` | `symbol_xrefs` | positive | Import/symbol-anchored localization — code calling a relevant helper. | Matching dynamic symbol / relocation / PLT label. |
| `symbol_xref_window` | `symbol_xrefs` | positive | Memory-safety fix at a call site — added guard/bounds check before a libc call. | Disassembly window referencing a symbol's address. |
| `no_symbol_xref_anchor` | `symbol_xrefs` | negative | Symbol-anchored localization failed — import not called / not present. | No symbol/reloc/PLT anchor found for the regex. |
| `allocation_candidate_summary` | `symbol_xrefs` | positive | Integer-overflow-before-alloc fix — allocator call site with recovered count/size args + null-check. | Allocator call-site candidates surfaced by symbol xrefs, with recovered immediate count/size args and a following null-check flag. |
| `disassembly_match` | `objdump_grep` | positive | Instruction-shape fix — matched guard / return-code / changed call line. | Disassembly line(s) matching the regex, with context. |
| `no_disassembly_match` | `objdump_grep` | negative | Absent instruction shape — expected guard/op not found. | No disassembly line matched the regex. |
| `disassembly_window` | `objdump_window` | positive | Exact fix shape at a site — guard / bounds / field-assignment / bounded call. | Bounded disassembly window between two addresses. |
| `disassembly_semantic_ops` | `objdump_window` | positive | Distilled fix-relevant ops — cmp/branch/store/call near the site. | Semantic-operation summary distilled from the window. |
| `bitmask_flag_decision` | `objdump_window` (bitmask flow) | positive | Flag/bitmask-gating fix — added/changed flag test-and-branch (validation/feature bit). | Local bitmask/flag test-and-branch decision facts. |
| `null_guarded_use` | `null_guard_flow` | positive | NPD fix present — target pointer use is preceded by a local NULL guard. | A tracked pointer use-site has a nearby prior compare/test against zero plus branch. |
| `null_guard_missing_use` | `null_guard_flow` | negative | NPD vulnerable path — target pointer use lacks a nearby prior NULL guard. | A tracked pointer is dereferenced or used at a sink without a local prior guard. |
| `no_null_guard_for_target` | `null_guard_flow` | negative | NPD vulnerable path — no guard was found for the tracked pointer in the analyzed window. | The window contains tracked pointer use-sites but no NULL guard for that target. |
| `struct_access_summary` | `struct_accesses` | positive | Struct field init/assignment fix — base+offset writes evidencing a new field set. | Summary of struct-like base+offset reads/writes. |
| `struct_access_sequence` | `struct_accesses` | positive | Ordered field init/propagation fix — sequence of struct field reads/writes. | Ordered sequence of struct field accesses. |
| `struct_copy_cluster_summary` | `struct_copy_search` | positive | Field-propagation fix — summary of a struct field-copy cluster. | Summary of a cluster of field-copy pairs. |
| `struct_copy_cluster` | `struct_copy_search` | positive | Field-propagation fix candidate — address range of struct copies. | A candidate cluster (address range) of struct copies. |
| `struct_copy_pair` | `struct_copy_search` | positive | Single field-propagation fix — one src→dst field copy. | A single src→dst struct field-copy pair. |
| `allocation_size_flow_summary` | `allocation_size_flow_search` | positive | Integer-overflow-before-alloc fix — size arithmetic / overflow-guard summary near an allocator. | Summary of size arithmetic / overflow guards near an allocator call. |
| `allocation_size_flow_window` | `allocation_size_flow_search` | positive | Integer-overflow-before-alloc fix — disassembly of an allocator size flow. | Disassembly window of an allocator call-site size flow. |
| `binary_platform_profile` | `platform_applicability_scan` · `core/pregate.py` | positive | Architecture/word-size scope — ELF class/machine/`size_t` for platform applicability. | Target ELF class / machine / inferred `size_t` width. |
| `applicability_precondition_mismatch` | `platform_applicability_scan` | negative | `not_affected` by platform — binary contradicts the arch/word-size precondition. | Binary platform contradicts the CVE's architecture/word-size precondition. |
| `target_feature_marker_present` | `feature_applicability_scan` | positive | Affected feature in scope — the vulnerable feature/backend is compiled/linked in. | An optional feature/backend marker is linked/compiled into the artifact. |
| `target_feature_path_absent` | `feature_applicability_scan` · `core/pregate.py` | negative | `not_affected` / `absent` by missing feature — backend/feature path not compiled or linked. | A feature/backend path is not compiled or linked in. |
