# Curl Stripped: StraightDetect vs AgenticDetect

统计时间：2026-06-08

## 统计口径

本报告统计非 deployed 的最近一次 `curl_stripped` 全量 run。

| 系统 | Run |
|---|---|
| StraightDetect | `/home/zhangxb/ClawSpace/agent/straight_detect/runs/curl_stripped_o0_results.json` |
| AgenticDetect | `/home/zhangxb/ClawSpace/agent/agenticdetect/runs/curl_stripped_o0_pro_full` |

`not_affected` 准确度参考：

`/home/zhangxb/ClawSpace/agent/straight_detect/groundtruth/curl_notaffected.json`

该 sidecar 中记录的真 `not_affected` 共 9 个 testcase。

## 五个指标

| 系统 | A | P | R | F1 | DSR | TP | TN | FP | FN | inconclusive | error | not_affected |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| StraightDetect | 0.9659 | 0.9394 | 1.0000 | 0.9688 | 0.9341 | 93 | 77 | 6 | 0 | 0 | 6 | 32 |
| AgenticDetect pro | 0.8958 | 0.9651 | 0.8300 | 0.8925 | 0.8473 | 83 | 89 | 3 | 17 | 11 | 0 | 11 |

## Not Affected 准确度

| 系统 | predicted | hit | extra | missed | precision | recall |
|---|---:|---:|---:|---:|---:|---:|
| StraightDetect | 32 | 9 | 23 | 0 | 28.1% | 100.0% |
| AgenticDetect pro | 11 | 9 | 2 | 0 | 81.8% | 100.0% |

AgenticDetect pro 多判的 2 个：

| CVE | Binary |
|---|---|
| CVE-2021-22898 | curl-7.78.0-curl |
| CVE-2021-22898 | curl-7.79.0-curl |

StraightDetect 多判的 23 个主要集中在：

| CVE | 多判数量 |
|---|---:|
| CVE-2016-8618 | 6 |
| CVE-2017-8816 | 6 |
| CVE-2017-8818 | 5 |
| CVE-2017-9502 | 6 |

## Token 与时间

| 系统 | wall time | case wall sum | total tokens | input/prompt | cached | output/completion | model turns |
|---|---:|---:|---:|---:|---:|---:|---:|
| StraightDetect | 10845.9s / 180.8min | 10840.1s | 22.85M | 22.38M input | 17.71M | 473,965 output | 36 |
| AgenticDetect pro | 1333.6s / 22.2min | 9134.8s | 54.08M | 53.63M prompt | 51.18M | 449,445 completion | 1072 |

StraightDetect token 口径为 `input_tokens + output_tokens`，另有 `reasoning_output_tokens=328,236`。AgenticDetect token 口径来自 `batch_metrics.json` 的 `usage_totals.total_tokens`。

## 结论

StraightDetect 在当前 curl stripped run 上整体指标更高，尤其 recall、F1 和 DSR 更好；但它的 `not_affected` 输出过宽，precision 只有 28.1%。

AgenticDetect pro 的整体 patch-presence 指标低一些，主要受 FN 和 inconclusive 影响；但 `not_affected` 更保守，precision 达到 81.8%，没有漏掉 sidecar 中的真 `not_affected`。

