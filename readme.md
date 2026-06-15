我需要你以你认为合适的方式对binutils/下的二进制文件进行patch presence检测，即查看某个CVE的patch是否存在于binary中。testset.json中是每个CVE的待检测目标，你可以在binutils/目录下找到对应的binary，如果找不到就输出一个not found的错误。binutils.json中描述了每个CVE的一些metadata，用于检测。

我需要你给出json格式的答案，每个CVE在testset的那几个binary上你的判断是什么。

你可以在当前会话批量去做也可以用subagent

不可以使用联网搜索，版本号匹配，你的每个推断都要有清晰的逻辑推理和证据佐证。
你可以使用本机的任意工具，或者编写代码，但是不可以作弊。

## codex_patch_presence_batch.py provider 参数

现在 `codex_patch_presence_batch.py` 支持 `--provider`：

- `--provider openai`：沿用当前 Codex/OpenAI 配置
- `--provider dpsk`：给 `codex exec` 注入本地 DeepSeek 代理配置

示例：

```bash
python3 /home/zhangxb/ClawSpace/agent/straight_detect/codex_patch_presence_batch.py \
  --project curl \
  --provider dpsk \
  --dpsk-base-url http://127.0.0.1:18080/v1 \
  --dpsk-model deepseek-v4-flash \
  --reasoning-effort high
```

## Dataset 文件布局

新的实验数据优先放在 `datasets/<dataset-name>/`：

```text
datasets/curl_dataset4ppt_20/testset.json
datasets/curl_dataset4ppt_20/groundtruth.json
datasets/curl_deployed/testset.json
datasets/curl_deployed/groundtruth.json
```

`testset.json` 和 `groundtruth.json` 只支持 dataset export list 格式，不再支持旧的 `CVE -> [binary]` 或 `CVE -> {vuln, patch}` 顶层对象格式。`testset/` 和 `groundtruth/` 下仍保留部分历史数据，用于旧实验或对照。

| Project | PS³ A | PS³ P | PS³ R | PS³ F1 | PS³ DSR | React A | React P | React R | React F1 | React DSR | BinXray A | BinXray P | BinXray R | BinXray
F1 | BinXray DSR | PatchDiscovery A | PatchDiscovery P | PatchDiscovery R | PatchDiscovery F1 | PatchDiscovery DSR | Robin A | Robin P | Robin R | Robin
F1 | Robin DSR | Ours A | Ours P | Ours R | Ours F1 | Ours DSR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|--
-:|
| Binutils | 0.74 | 0.86 | 0.77 | 0.81 | 0.63 | 0.67 | 0.51 | 0.88 | 0.64 | 0.41 | 0.89 | 0.97 | 0.87 | 0.92 | 0.72 | 0.78 | 0.95 | 0.73 | 0.83 | 0.75 |
0.90 | 0.87 | 0.80 | 0.83 | 0.18 | 0.92 | 0.92 | 0.97 | 0.94 | 0.87 |
