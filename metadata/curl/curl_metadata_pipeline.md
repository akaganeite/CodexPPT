# curl metadata pipeline run

## 产物
- `initial_project_json`: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl.json` (存在)
- `initial_stats`: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_initial_build_stats.json` (存在)
- `source_full`: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.full.json` (存在)
- `source_min`: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.min.json` (存在)
- `behavior`: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.behavior.json` (存在)
- `report`: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_metadata_pipeline.md` (存在)

## 输入
- project: `curl`
- output_dir: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl`
- repo_path: `/home/zhangxb/patch/related-works/CVE-Dataset/target/curl`

## 步骤
### 1. build_initial_project_json
- status: `ok`
- returncode: `0`
- seconds: `0.07`
- log: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/logs/01_build_initial_project_json.log`

```bash
/usr/bin/python3 /home/zhangxb/ClawSpace/agent/straight_detect/metadata/build_initial_project_json.py --project curl --dataset-root /home/zhangxb/patch/related-works/CVE-Dataset/New --output /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl.json --stats-output /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_initial_build_stats.json
```

### 2. project_source_analysis
- status: `ok`
- returncode: `0`
- seconds: `5.36`
- log: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/logs/02_project_source_analysis.log`

```bash
/usr/bin/python3 /home/zhangxb/ClawSpace/agent/straight_detect/metadata/project_source_analysis.py --input /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl.json --project curl --repo-path /home/zhangxb/patch/related-works/CVE-Dataset/target/curl --output-full /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.full.json --output-min /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.min.json
```

### 3. generate_behavior_analysis_deepseek
- status: `ok`
- returncode: `0`
- seconds: `1967.31`
- log: `/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/logs/03_generate_behavior_analysis_deepseek.log`

```bash
/usr/bin/python3 /home/zhangxb/ClawSpace/agent/straight_detect/metadata/generate_behavior_analysis_deepseek.py --input /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.min.json --output /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.behavior.json --resume --api-timeout 300
```

## 初始 JSON 统计
- input_source_diff_cves: `52`
- selected_cves: `52`
- emitted_cves: `52`
- total_functions: `94`
- diff_files_found: `52`
- diff_files_missing: `0`
- cveinfo_found: `52`
- cveinfo_missing: `0`
- functions_with_file: `94`
- functions_without_file: `0`
- change_type.added: `11`
- change_type.deleted: `4`
- change_type.modified: `79`
- inferred_by.function_definition_hunk_match: `16`
- inferred_by.function_header_hunk_match: `72`
- inferred_by.function_reference_hunk_match: `6`

## 源码分析统计
- cve_count: `52`
- function_count: `94`
- analysis_status.failed: `4`
- analysis_status.ok: `90`

## DeepSeek 行为分析统计
- cve_count: `52`
- analyzed: `52`
- errors: `0`

## 说明
- 第一步生成的 project.json 是 `project_source_analysis.py` 的输入，默认只保留 diff 文件路径，不内嵌 hunk 文本。
- 初始 JSON 不提供函数源码；后续源码分析脚本会重新解析 diff，并基于 git commit 补充 reduced source context。
- 如果 `repo_path` 为空或不是 git 仓库，源码分析会跳过；需要提供可 `git show <commit>:<file>` 的项目仓库。
