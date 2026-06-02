# Project JSON metadata pipeline

这套脚本用于从 CVE-Dataset 的 `New` 数据生成 `project_source_analysis.py` 可消费的初始 `project.json`，再串联源码分析和 DeepSeek 行为 metadata 抽取。

## 脚本

- `build_initial_project_json.py`: 从 `source_diff.json`、`diff_files/*.diff`、`<project>_parsed.json` 构建初始 `project.json`。只保留后续分析必需字段；diff parser 仅用于推断函数所在文件。
- `project_source_analysis.py`: 对初始 `project.json` 里的 CVE/function 做源码级 patch delta、source-sink flow、reduced function code 提取。
- `generate_behavior_analysis_deepseek.py`: 基于 compact source metadata 调 DeepSeek 生成 root-cause 和 patch-intent metadata。
- `run_metadata_pipeline.py`: 驱动前三个脚本，并生成 Markdown 运行报告。

## 输入约定

默认读取：

```text
/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/<project>/source_diff.json
/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/<project>/diff_files/*.diff
/home/zhangxb/patch/related-works/CVE-Dataset/New/cveinfo/<project>/<project>_parsed.json
```

`source_diff.json` 兼容两种结构：

```json
{"curl": {"CVE-...": {"commit": "...", "analysis": [{"function": "..."}]}}}
```

```json
{"CVE-...": {"commit": "...", "analysis": [{"function": "..."}]}}
```

## 初始 project.json 输出结构

每个 CVE 输出为：

```json
{
  "CVE-...": {
    "functions": ["..."],
    "summary": "...",
    "cwe": ["CWE-..."],
    "diff_related": [{"file": "/abs/path/to/diff"}],
    "function_code": {
      "commit": "...",
      "by_function": {
        "...": {"file": "repo/relative/source.c"}
      }
    }
  }
}
```

注意：初始 JSON 只负责提供 commit、函数、diff 文件路径、CVE summary/CWE，以及尽量从 diff hunk 推断函数所在文件。`project_source_analysis.py` 会根据 diff 文件路径重新解析 patch hunk，并从 git repo 读取 commit 源码生成更精确的 reduced source context。

## 直接构建初始 JSON

```bash
python3 metadata/build_initial_project_json.py \
  --project curl \
  --output metadata/curl/curl.json \
  --stats-output metadata/curl/curl_initial_build_stats.json
```

单 CVE 或小批量测试：

```bash
python3 metadata/build_initial_project_json.py \
  --project curl \
  --cve CVE-2014-3613 \
  --output metadata/curl/curl.json \
  --stats-output metadata/curl/curl_initial_build_stats.json
```

## 跑完整 pipeline

```bash
python3 metadata/run_metadata_pipeline.py \
  --project curl \
  --repo-path /path/to/curl-git-repo \
  --behavior-mode auto
```

常用测试命令：

```bash
python3 metadata/run_metadata_pipeline.py \
  --project curl \
  --limit 3 \
  --behavior-mode skip \
  --continue-on-error
```

如果本机没有可用的 curl git repo，driver 会跳过 `project_source_analysis.py`，并在 `metadata/curl/curl_metadata_pipeline.md` 里记录原因。要跑源码分析，需要传入一个能执行 `git show <commit>:<file>` 的 curl 仓库。

## 产物

默认写到 `metadata/<project>/`：

- `<project>.json`: 初始 project JSON。
- `<project>_initial_build_stats.json`: 初始构建统计。
- `<project>_project_source_analysis.full.json`: 源码分析 full/debug 输出。
- `<project>_project_source_analysis.min.json`: 源码分析 compact 输出。
- `<project>_project_source_analysis.behavior.json`: DeepSeek 行为 metadata 输出。
- `<project>_metadata_pipeline.md`: pipeline 运行报告。
- `logs/*.log`: 每一步 stdout/stderr。

## DeepSeek 配置

`generate_behavior_analysis_deepseek.py` 需要 `DEEPSEEK_API_KEY`。默认：

```text
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-pro
```

`run_metadata_pipeline.py --behavior-mode auto` 只有在当前环境已经能看到 `DEEPSEEK_API_KEY` 时才会真实调用 DeepSeek，否则会自动执行 `--dry-run`，用于验证 prompt 输入。
