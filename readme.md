# straight_detect — 二进制 patch-presence 检测

用 `codex exec` 驱动的 LLM agent,对目标二进制做 **patch-presence 检测**:判断某个 CVE 的
patch 是否存在于 binary 中(`present` / `absent` / `not_affected` / `inconclusive` /
`not_found`)。检测本身由 agent 完成,本仓库的 Python wrapper 负责构造 prompt、批量调度、
解析校验 JSON 结果、并对照 groundtruth 算 metrics。

入口是 `codex_patch_presence_batch.py`(`codex_batch/` 包的薄壳)。架构细节见 `CLAUDE.md`。

## 检测原则(写进 prompt,agent 必须遵守)

- 不可联网搜索。
- 不可用版本号匹配作为证据。
- 不可读取 metadata 里引用的源码文件;每个推断都要有本地二进制证据和清晰逻辑。
- 只看 `--target-dir` 内的二进制 + 供给的 `safe_objdump` helper。

## 运行示例

在仓库根目录运行。下面是 curl stripped 二进制、OpenAI/Codex provider 的 binarywise 跑法:

```bash
python3 codex_patch_presence_batch.py \
  --project-json metadata/curl/curl_project_source_analysis.behavior.json \
  --testset-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/testset.json \
  --target-dir /home/zhangxb/extdisk/dataset4ppt/curl/binaries/target/curl_stripped \
  --groundtruth-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/groundtruth_with_not_affected.json \
  --opt o0 \
  --output runs/curl_stripped_o0_results.json \
  --raw-dir runs/curl_stripped_o0_raw \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --provider openai \
  --codex-json-events \
  --timeout 3600
```

常用辅助 flag:`--jobs N`(并发跑 N 个 `codex exec` 任务,默认 1=串行;调高提速但有 429
限流风险,调低 `--jobs` 就是限流手段)、`--resume`(跳过 `--output` 里已有的任务)、
`--retry-errors`(配合 `--resume` 只重跑 `status=error`)、`--dry-run`(只写 prompt 不调
模型)、`--limit` / `--cve`(缩小范围)。完整参数见 `codex_batch/cli.py`。

> 并发(`--jobs > 1`)下:进度 `[i/total]` 的 `i` 是"第几个进入运行"而非完成顺序;output
> 落盘顺序非确定但最终内容一致(每任务写自己的 key);Ctrl-C 会取消未启动任务、等在跑的
> 任务自然结束,已完成结果已落盘,`--resume` 可接续。

> groundtruth JSON 必须放在 `--target-dir` 和 `--cd` 之外,否则 wrapper 会直接报错,以保证
> agent 看不到答案。

## provider 参数

`--provider` 选择 `codex exec` 的后端:

- `--provider openai`:沿用当前 Codex/OpenAI 配置。
- `--provider dpsk`:把 Codex 路由到本地 DeepSeek 兼容代理。
- `--provider pptagent`:把 Codex 路由到 PPTAgent OpenAI-compatible Responses endpoint。
- `--provider volc`:直连 Volcengine Ark Responses endpoint,默认读 `VOLC_AGENT_PLAN_API_KEY`。

dpsk 示例(其余 flag 同上):

```bash
python3 codex_patch_presence_batch.py \
  --project-json metadata/curl/curl_project_source_analysis.behavior.json \
  --testset-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/testset.json \
  --target-dir /home/zhangxb/extdisk/dataset4ppt/curl/binaries/target/curl_stripped \
  --groundtruth-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/groundtruth_with_not_affected.json \
  --opt o0 \
  --output runs/curl_stripped_o0_dpsk_results.json \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --provider dpsk \
  --dpsk-base-url http://127.0.0.1:18080/v1 \
  --dpsk-model deepseek-v4-flash \
  --reasoning-effort high \
  --codex-json-events \
  --timeout 3600
```

pptagent 示例(默认读 `PPTAGENT_API_KEY`,默认模型 `glm-5.2`):

```bash
python3 codex_patch_presence_batch.py \
  --project-json metadata/curl/curl_project_source_analysis.behavior.json \
  --testset-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/testset.json \
  --target-dir /home/zhangxb/extdisk/dataset4ppt/curl/binaries/target/curl_stripped \
  --groundtruth-json /home/zhangxb/extdisk/dataset4ppt/curl/exports/groundtruth_with_not_affected.json \
  --opt o0 \
  --output runs/curl_stripped_o0_pptagent_results.json \
  --prompt-template prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --provider pptagent \
  --pptagent-base-url http://192.168.104.61:4000/v1 \
  --pptagent-model glm-5.2 \
  --codex-json-events \
  --timeout 3600
```

## 数据文件格式

`--testset-json` 和 `--groundtruth-json` **只支持 dataset export list 格式**(顶层是 list,
每项含 `CVE` 以及 `binaries` 或 `vuln`/`patch`/`not_affected` 字符串列表):

```json
[
  {"CVE": "CVE-...", "functions": [...], "binaries": [...]},
  {"CVE": "CVE-...", "vuln": [...], "patch": [...], "not_affected": [...]}
]
```

旧的 `CVE -> [binary]` / `CVE -> {vuln, patch}` 顶层对象格式已不再支持。当前实验用的数据集
导出在 `/home/zhangxb/extdisk/dataset4ppt/<project>/exports/` 下;仓库内 `testset/` 和
`groundtruth/` 保留的是历史数据(旧格式,当前代码不再加载),仅供对照。

`--project-json` 是 metadata 流水线的产物 `metadata/<project>/*_project_source_analysis.behavior.json`
(含 root-cause / patch-intent / behavior-changes 等检测所需的语义 metadata)。

## 实验结果(参考)

| Project | PS³ A | PS³ P | PS³ R | PS³ F1 | PS³ DSR | React A | React P | React R | React F1 | React DSR | BinXray A | BinXray P | BinXray R | BinXray F1 | BinXray DSR | PatchDiscovery A | PatchDiscovery P | PatchDiscovery R | PatchDiscovery F1 | PatchDiscovery DSR | Robin A | Robin P | Robin R | Robin F1 | Robin DSR | Ours A | Ours P | Ours R | Ours F1 | Ours DSR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Binutils | 0.74 | 0.86 | 0.77 | 0.81 | 0.63 | 0.67 | 0.51 | 0.88 | 0.64 | 0.41 | 0.89 | 0.97 | 0.87 | 0.92 | 0.72 | 0.78 | 0.95 | 0.73 | 0.83 | 0.75 | 0.90 | 0.87 | 0.80 | 0.83 | 0.18 | 0.92 | 0.92 | 0.97 | 0.94 | 0.87 |
