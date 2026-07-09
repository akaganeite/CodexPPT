# pptagent vs codex

统一统计 curl20、OpenSSL、libxml2-10、ImageMagick-10 的 stripped binarywise patch-presence 检测结果。Metrics 保留两位小数；Token/Time 同时给出单 run 和按配置汇总。

## Settings

| project | method | model | run/results path |
| --- | --- | --- | --- |
| curl20 | pptagent | deepseek-v4-flash no-thinking | `/home/zhangxb/ClawSpace/codex/pptagent/runs/curl_20_stripped_flash_no_thinking` |
| curl20 | codex exec | GPT default | `/home/zhangxb/ClawSpace/agent/straight_detect/runs/curl/curl_dataset4ppt_20_binarywise_o0_stripped_gpt_20260616_092813_results.json` |
| curl20 | codex exec | deepseek-v4-flash no-thinking | `/home/zhangxb/ClawSpace/agent/straight_detect/runs/curl/curl20_binarywise_stripped_dpsk_flash_off_20260615_214919_results.json` |
| openssl | pptagent | deepseek-v4-flash no-thinking | `/home/zhangxb/ClawSpace/codex/pptagent/runs/openssl_stripped_flash_no_thinking` |
| openssl | codex exec | GPT default | `/home/zhangxb/ClawSpace/agent/straight_detect/runs/openssl/openssl_dataset4ppt_binarywise_o0_stripped_gpt_20260616_120704_raw/openssl_dataset4ppt_binarywise_o0_stripped_gpt_20260616_120704_results.json` |
| openssl | codex exec | deepseek-v4-flash no-thinking | `/home/zhangxb/ClawSpace/agent/straight_detect/runs/openssl/openssl_o0_stripped_dpsk_20260618_095702_results.json` |
| libxml2-10 | pptagent | deepseek-v4-flash no-thinking | `/home/zhangxb/ClawSpace/codex/pptagent/runs/libxml2_10` |
| libxml2-10 | codex exec | GPT default | `/home/zhangxb/ClawSpace/agent/straight_detect/runs/libxml2/10_o0_gpt_results.json` |
| libxml2-10 | codex exec | deepseek-v4-flash no-thinking | `/home/zhangxb/ClawSpace/agent/straight_detect/runs/libxml2/10_o0_dpsk_results.json` |
| imagemagick-10 | pptagent | deepseek-v4-flash no-thinking | `/home/zhangxb/ClawSpace/codex/pptagent/runs/imagemagick_10_stripped_flash` |
| imagemagick-10 | codex exec | GPT default | `/home/zhangxb/ClawSpace/agent/straight_detect/runs/imagemagick/imagemagick_10_o0_stripped_gpt_20260622_112210_results.json` |
| imagemagick-10 | codex exec | deepseek-v4-flash no-thinking | `/home/zhangxb/ClawSpace/agent/straight_detect/runs/imagemagick/imagemagick_10_o0_stripped_dpsk_flash_off_20260622_114157_results.json` |

## Metrics

| project | method | model | A | P | R | F1 | DSR_binary | not affected A | total DSR |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| curl20 | pptagent | deepseek-v4-flash no-thinking | 0.98 | 0.98 | 0.98 | 0.98 | 0.94 | 1.00 | 0.96 |
| curl20 | codex exec | GPT default | 0.95 | 0.93 | 0.98 | 0.95 | 0.95 | 1.00 | 0.97 |
| curl20 | codex exec | deepseek-v4-flash no-thinking | 0.90 | 0.86 | 0.95 | 0.90 | 0.85 | 0.69 | 0.80 |
| openssl | pptagent | deepseek-v4-flash no-thinking | 0.99 | 0.98 | 1.00 | 0.99 | 0.92 | 0.80 | 0.92 |
| openssl | codex exec | GPT default | 0.98 | 0.98 | 0.98 | 0.98 | 0.94 | 0.80 | 0.93 |
| openssl | codex exec | deepseek-v4-flash no-thinking | 0.96 | 0.93 | 0.98 | 0.96 | 0.80 | 0.25 | 0.79 |
| libxml2-10 | pptagent | deepseek-v4-flash no-thinking | 1.00 | 1.00 | 1.00 | 1.00 | 0.95 | 0.00 | 0.90 |
| libxml2-10 | codex exec | GPT default | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.98 |
| libxml2-10 | codex exec | deepseek-v4-flash no-thinking | 1.00 | 1.00 | 1.00 | 1.00 | 0.95 | 0.00 | 0.93 |
| imagemagick-10 | pptagent | deepseek-v4-flash no-thinking | 0.90 | 0.94 | 0.91 | 0.93 | 0.83 | 0.00 | 0.80 |
| imagemagick-10 | codex exec | GPT default | 0.80 | 0.83 | 0.88 | 0.86 | 0.77 | 0.00 | 0.74 |
| imagemagick-10 | codex exec | deepseek-v4-flash no-thinking | 0.76 | 0.78 | 0.91 | 0.84 | 0.75 | 0.00 | 0.72 |

## Testcase Counts

| project | method | model | TC | TP | TN | FP | FN | error | inconclusive | notaffected |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| curl20 | pptagent | deepseek-v4-flash no-thinking | 120 | 41 | 38 | 1 | 1 | 0 | 3 | 36 |
| curl20 | codex exec | GPT default | 120 | 41 | 39 | 3 | 1 | 0 | 0 | 36 |
| curl20 | codex exec | deepseek-v4-flash no-thinking | 121 | 38 | 34 | 6 | 2 | 5 | 0 | 25 |
| openssl | pptagent | deepseek-v4-flash no-thinking | 136 | 54 | 67 | 1 | 0 | 0 | 9 | 4 |
| openssl | codex exec | GPT default | 136 | 51 | 72 | 1 | 1 | 0 | 6 | 4 |
| openssl | codex exec | deepseek-v4-flash no-thinking | 126 | 43 | 55 | 3 | 1 | 15 | 5 | 1 |
| libxml2-10 | pptagent | deepseek-v4-flash no-thinking | 60 | 27 | 27 | 0 | 0 | 0 | 3 | 0 |
| libxml2-10 | codex exec | GPT default | 60 | 31 | 28 | 0 | 0 | 0 | 0 | 0 |
| libxml2-10 | codex exec | deepseek-v4-flash no-thinking | 60 | 30 | 26 | 0 | 0 | 3 | 0 | 0 |
| imagemagick-10 | pptagent | deepseek-v4-flash no-thinking | 54 | 32 | 11 | 2 | 3 | 0 | 2 | 0 |
| imagemagick-10 | codex exec | GPT default | 54 | 30 | 10 | 6 | 4 | 0 | 2 | 0 |
| imagemagick-10 | codex exec | deepseek-v4-flash no-thinking | 54 | 32 | 7 | 9 | 3 | 1 | 0 | 0 |

## Token And Time

| project | method | model | total tokens | total percase | reasoning tokens | cache-miss input | output tokens | wall s | avg wall s/TC | tool calls | tool calls percase |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| curl20 | pptagent | deepseek-v4-flash no-thinking | 95,479,295 | 795660.79 | 0 | 7,093,843 | 756,652 | 8333.22 | 69.44 | 2,165 | 18.04 |
| curl20 | codex exec | GPT default | 20,701,477 | 172512.31 | 59,091 | 6,655,420 | 241,686 | 7762.74 | 64.69 | 1,203 | 10.03 |
| curl20 | codex exec | deepseek-v4-flash no-thinking | 318,543,380 | 2654528.17 | 0 | 6,356,390 | 1,763,438 | 24355.39 | 202.96 | 7,702 | 64.18 |
| openssl | pptagent | deepseek-v4-flash no-thinking | 230,906,800 | 1697844.12 | 0 | 13,464,815 | 1,660,481 | 20911.76 | 153.76 | 5,194 | 38.19 |
| openssl | codex exec | GPT default | 52,068,010 | 382853.01 | 175,608 | 11,915,870 | 496,340 | 17071.20 | 125.52 | 2,035 | 14.96 |
| openssl | codex exec | deepseek-v4-flash no-thinking | 708,809,479 | 5211834.40 | 0 | 9,821,563 | 4,081,804 | 50878.91 | 374.11 | 11,571 | 85.08 |
| libxml2-10 | pptagent | deepseek-v4-flash no-thinking | 40,782,761 | 679712.68 | 0 | 3,940,855 | 421,682 | 4263.77 | 71.06 | 1,148 | 19.13 |
| libxml2-10 | codex exec | GPT default | 12,234,923 | 203915.38 | 157,027 | 5,807,210 | 262,622 | 6725.31 | 112.09 | 658 | 10.97 |
| libxml2-10 | codex exec | deepseek-v4-flash no-thinking | 139,199,355 | 2319989.25 | 0 | 3,181,823 | 826,364 | 10297.28 | 171.62 | 2,744 | 45.73 |
| imagemagick-10 | pptagent | deepseek-v4-flash no-thinking | 65,987,357 | 1221988.09 | 0 | 5,376,338 | 481,099 | 6319.31 | 117.02 | 1,439 | 26.65 |
| imagemagick-10 | codex exec | GPT default | 14,771,928 | 273554.22 | 39,478 | 5,056,014 | 141,076 | 4264.25 | 78.97 | 669 | 12.39 |
| imagemagick-10 | codex exec | deepseek-v4-flash no-thinking | 176,820,473 | 3274453.20 | 0 | 3,850,844 | 979,357 | 13072.86 | 242.09 | 3,597 | 66.61 |

## Token And Time By Config

| method | model | projects | TC | total tokens | total percase | reasoning tokens | cache-miss input | output tokens | wall s | avg wall s/TC | tool calls | tool calls percase |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| pptagent | deepseek-v4-flash no-thinking | curl20, openssl, libxml2-10, imagemagick-10 | 370 | 433,156,213 | 1170692.47 | 0 | 29,875,851 | 3,319,914 | 39828.06 | 107.64 | 9,946 | 26.88 |
| codex exec | GPT default | curl20, openssl, libxml2-10, imagemagick-10 | 370 | 99,776,338 | 269665.78 | 431,204 | 29,434,514 | 1,141,724 | 35823.50 | 96.82 | 4,565 | 12.34 |
| codex exec | deepseek-v4-flash no-thinking | curl20, openssl, libxml2-10, imagemagick-10 | 370 | 1,343,372,687 | 3630736.99 | 0 | 23,210,620 | 7,650,963 | 98604.44 | 266.50 | 25,614 | 69.23 |

## PerfAdv: pptagent vs codex+dpsk

PerfAdv = `(codex+dpsk - pptagent) / codex+dpsk`，正数表示 pptagent 更省。这里聚合双方都有完整结果的项目；当前包含 `curl20`、`openssl`、`libxml2-10` 和 `imagemagick-10`。

| metric | pptagent | codex+dpsk | PerfAdv |
| --- | ---: | ---: | ---: |
| tool calls percase | 26.88 | 69.23 | 61.17% |
| total tokens percase | 1170692.47 | 3630736.99 | 67.76% |
| avg wall s/TC | 107.64 | 266.50 | 59.61% |

## Error Testcases

包含 FP/FN、not_affected 误判、inconclusive、error、not_found。

### curl20 / pptagent / deepseek-v4-flash no-thinking

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| inconclusive | CVE-2017-2629 | `curl-7.51.0-libcurl-gcc-O0` | absent | inconclusive |
| FN | CVE-2018-0500 | `curl-7.62.0-libcurl-gcc-O0` | present | absent |
| inconclusive | CVE-2018-1000007 | `curl-7.57.0-libcurl-gcc-O0` | absent | inconclusive |
| inconclusive | CVE-2019-5482 | `curl-7.65.2-libcurl-gcc-O0` | absent | inconclusive |
| FP | CVE-2020-8177 | `curl-7.69.1-curl-gcc-O0` | absent | present |

### curl20 / codex exec / GPT default

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| FP | CVE-2016-9594 | `curl-7.50.3-libcurl-gcc-O0` | absent | present |
| FP | CVE-2016-9594 | `curl-7.51.0-libcurl-gcc-O0` | absent | present |
| FP | CVE-2017-2629 | `curl-7.52.0-libcurl-gcc-O0` | absent | present |
| FN | CVE-2018-0500 | `curl-7.62.0-libcurl-gcc-O0` | present | absent |

### curl20 / codex exec / deepseek-v4-flash no-thinking

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| error | CVE-2016-3739 | `curl-7.48.0-libcurl-gcc-O0` | not_affected | error |
| not_affected_FN | CVE-2016-8618 | `curl-7.50.1-libcurl-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2016-8618 | `curl-7.51.0-libcurl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2016-8618 | `curl-7.52.0-libcurl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2016-8618 | `curl-7.52.1-libcurl-gcc-O0` | not_affected | present |
| FP | CVE-2016-9594 | `curl-7.50.3-libcurl-gcc-O0` | absent | present |
| FP | CVE-2016-9594 | `curl-7.51.0-libcurl-gcc-O0` | absent | present |
| FP | CVE-2017-2629 | `curl-7.52.1-libcurl-gcc-O0` | absent | present |
| error | CVE-2017-2629 | `curl-7.53.1-libcurl-gcc-O0` | present | error |
| FN | CVE-2017-2629 | `curl-7.54.0-libcurl-gcc-O0` | present | absent |
| not_affected_FN | CVE-2017-8816 | `curl-7.55.1-libcurl-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2017-8816 | `curl-7.56.0-libcurl-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2017-8816 | `curl-7.56.1-libcurl-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2017-8816 | `curl-7.57.0-libcurl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2017-8816 | `curl-7.58.0-libcurl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2017-8816 | `curl-7.59.0-libcurl-gcc-O0` | not_affected | present |
| FN | CVE-2018-0500 | `curl-7.62.0-libcurl-gcc-O0` | present | absent |
| error | CVE-2018-1000007 | `curl-7.59.0-libcurl-gcc-O0` | present | error |
| error | CVE-2019-5482 | `curl-7.65.2-libcurl-gcc-O0` | absent | error |
| error | CVE-2019-5482 | `curl-7.65.3-libcurl-gcc-O0` | absent | error |
| FP | CVE-2020-8177 | `curl-7.69.1-curl-gcc-O0` | absent | present |
| FP | CVE-2021-22901 | `curl-7.76.1-libcurl-gcc-O0` | absent | present |
| FP | CVE-2022-42916 | `curl-7.85.0-libcurl-gcc-O0` | absent | present |

### openssl / pptagent / deepseek-v4-flash no-thinking

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| not_affected_FN | CVE-2014-3572 | `openssl-1.1.0-openssl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2014-3572 | `openssl-1.1.0a-openssl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2014-3572 | `openssl-1.1.0b-openssl-gcc-O0` | not_affected | present |
| inconclusive | CVE-2015-0205 | `openssl-1.0.0o-openssl-gcc-O0` | absent | inconclusive |
| not_affected_FN | CVE-2015-0205 | `openssl-1.1.0-openssl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2015-0205 | `openssl-1.1.0a-openssl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2015-0205 | `openssl-1.1.0b-openssl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2015-0206 | `openssl-1.1.0-openssl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2015-0206 | `openssl-1.1.0a-openssl-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2015-0206 | `openssl-1.1.0b-openssl-gcc-O0` | not_affected | present |
| inconclusive | CVE-2015-0209 | `openssl-0.9.8-post-auto-reformat-openssl-gcc-O0` | absent | inconclusive |
| inconclusive | CVE-2015-0209 | `openssl-0.9.8-post-reformat-openssl-gcc-O0` | absent | inconclusive |
| FP | CVE-2015-0288 | `openssl-0.9.8-post-auto-reformat-openssl-gcc-O0` | absent | present |
| inconclusive | CVE-2015-0288 | `openssl-0.9.8-post-reformat-openssl-gcc-O0` | absent | inconclusive |
| inconclusive | CVE-2015-0288 | `openssl-1.1.0a-openssl-gcc-O0` | present | inconclusive |
| inconclusive | CVE-2015-1788 | `openssl-0.9.8zf-openssl-gcc-O0` | not_affected | inconclusive |
| not_affected_FN | CVE-2015-1788 | `openssl-1.0.0r-openssl-gcc-O0` | not_affected | present |
| inconclusive | CVE-2025-66199 | `openssl-3.3.6-openssl-gcc-O0` | not_affected | inconclusive |
| inconclusive | CVE-2025-66199 | `openssl-3.3.7-openssl-gcc-O0` | not_affected | inconclusive |
| not_affected_FN | CVE-2025-66199 | `openssl-3.4.3-openssl-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2025-66199 | `openssl-3.5.4-openssl-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2025-66199 | `openssl-3.6.0-openssl-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2026-28387 | `openssl-3.4.4-libcrypto-gcc-O0` | not_affected | present |
| inconclusive | CVE-2026-28388 | `openssl-3.5.5-libcrypto-gcc-O0` | not_affected | inconclusive |
| not_affected_FN | CVE-2026-31790 | `openssl-3.6.1-libcrypto-gcc-O0` | not_affected | absent |

### openssl / codex exec / GPT default

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| inconclusive | CVE-2015-0205 | `openssl-1.1.0-openssl-gcc-O0` | present | inconclusive |
| inconclusive | CVE-2015-0205 | `openssl-1.1.0a-openssl-gcc-O0` | present | inconclusive |
| inconclusive | CVE-2015-0205 | `openssl-1.1.0b-openssl-gcc-O0` | present | inconclusive |
| FN | CVE-2015-0206 | `openssl-1.1.0b-openssl-gcc-O0` | present | absent |
| FP | CVE-2015-0209 | `openssl-1.0.2-openssl-gcc-O0` | absent | present |
| inconclusive | CVE-2015-0288 | `openssl-1.1.0-openssl-gcc-O0` | present | inconclusive |
| not_affected_FN | CVE-2015-1788 | `openssl-1.0.0r-openssl-gcc-O0` | not_affected | absent |
| inconclusive | CVE-2025-66199 | `openssl-3.3.6-openssl-gcc-O0` | present | inconclusive |
| inconclusive | CVE-2025-66199 | `openssl-3.4.3-openssl-gcc-O0` | absent | inconclusive |

### openssl / codex exec / deepseek-v4-flash no-thinking

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| inconclusive | CVE-2014-3572 | `openssl-1.0.0o-openssl-gcc-O0` | absent | inconclusive |
| error | CVE-2014-3572 | `openssl-1.0.1j-openssl-gcc-O0` | absent | error |
| FN | CVE-2014-3572 | `openssl-1.1.0-openssl-gcc-O0` | present | absent |
| error | CVE-2015-0206 | `openssl-1.1.0-openssl-gcc-O0` | present | error |
| FP | CVE-2015-0209 | `openssl-0.9.8-post-reformat-openssl-gcc-O0` | absent | present |
| not_affected_FP | CVE-2015-0209 | `openssl-1.1.0b-openssl-gcc-O0` | present | not_affected |
| inconclusive | CVE-2015-0288 | `openssl-0.9.8-post-reformat-openssl-gcc-O0` | absent | inconclusive |
| inconclusive | CVE-2015-0288 | `openssl-1.0.2-openssl-gcc-O0` | absent | inconclusive |
| not_affected_FP | CVE-2015-1788 | `openssl-0.9.8zf-openssl-gcc-O0` | present | not_affected |
| error | CVE-2015-1788 | `openssl-1.0.0r-openssl-gcc-O0` | present | error |
| error | CVE-2015-1788 | `openssl-1.1.0b-openssl-gcc-O0` | present | error |
| error | CVE-2015-1789 | `openssl-1.1.0a-openssl-gcc-O0` | present | error |
| error | CVE-2015-1790 | `openssl-1.0.1m-openssl-gcc-O0` | absent | error |
| not_affected_FP | CVE-2025-15467 | `openssl-3.0.19-libcrypto-gcc-O0` | present | not_affected |
| not_affected_FP | CVE-2025-15467 | `openssl-3.0.20-libcrypto-gcc-O0` | present | not_affected |
| not_affected_FP | CVE-2025-15467 | `openssl-3.6.0-libcrypto-gcc-O0` | absent | not_affected |
| error | CVE-2025-15468 | `openssl-3.5.6-libssl-gcc-O0` | present | error |
| error | CVE-2025-15469 | `openssl-3.5.4-openssl-gcc-O0` | absent | error |
| not_found | CVE-2025-15469 | `openssl-3.5.6-openssl-gcc-O0` | present | not_found |
| not_found | CVE-2025-15469 | `openssl-3.6.0-openssl-gcc-O0` | absent | not_found |
| not_found | CVE-2025-4575 | `openssl-3.5.0-openssl-gcc-O0` | absent | not_found |
| error | CVE-2025-66199 | `openssl-3.3.6-openssl-gcc-O0` | present | error |
| not_affected_FP | CVE-2025-66199 | `openssl-3.3.7-openssl-gcc-O0` | present | not_affected |
| not_affected_FP | CVE-2025-66199 | `openssl-3.4.3-openssl-gcc-O0` | absent | not_affected |
| inconclusive | CVE-2025-66199 | `openssl-3.6.0-openssl-gcc-O0` | absent | inconclusive |
| error | CVE-2025-68160 | `openssl-3.5.4-libcrypto-gcc-O0` | absent | error |
| error | CVE-2025-69419 | `openssl-3.5.4-libcrypto-gcc-O0` | absent | error |
| error | CVE-2025-69420 | `openssl-3.6.0-libcrypto-gcc-O0` | absent | error |
| FP | CVE-2026-22795 | `openssl-3.5.4-openssl-gcc-O0` | absent | present |
| FP | CVE-2026-22796 | `openssl-3.5.4-openssl-gcc-O0` | absent | present |
| inconclusive | CVE-2026-22796 | `openssl-3.5.6-openssl-gcc-O0` | present | inconclusive |
| error | CVE-2026-28388 | `openssl-3.0.20-libcrypto-gcc-O0` | present | error |
| not_affected_FP | CVE-2026-28388 | `openssl-3.4.4-libcrypto-gcc-O0` | absent | not_affected |
| error | CVE-2026-31789 | `openssl-3.0.20-libcrypto-gcc-O0` | not_affected | error |
| not_affected_FN | CVE-2026-31789 | `openssl-3.4.4-libcrypto-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2026-31789 | `openssl-3.5.5-libcrypto-gcc-O0` | not_affected | absent |
| error | CVE-2026-31790 | `openssl-3.4.4-libcrypto-gcc-O0` | absent | error |

### libxml2-10 / pptagent / deepseek-v4-flash no-thinking

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| not_affected_FN | CVE-2013-0339 | `libxml2-2.9.0-libxml2-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2013-0339 | `libxml2-2.9.0-rc2-libxml2-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2016-1838 | `libxml2-2.9.4-libxml2-gcc-O0` | not_affected | present |
| inconclusive | CVE-2022-29824 | `libxml2-2.10.0-libxml2-gcc-O0` | present | inconclusive |
| inconclusive | CVE-2022-29824 | `libxml2-2.10.2-libxml2-gcc-O0` | present | inconclusive |
| inconclusive | CVE-2022-29824 | `libxml2-2.9.12-libxml2-gcc-O0` | absent | inconclusive |

### libxml2-10 / codex exec / GPT default

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| not_affected_FN | CVE-2016-1838 | `libxml2-2.9.4-libxml2-gcc-O0` | not_affected | present |

### libxml2-10 / codex exec / deepseek-v4-flash no-thinking

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| error | CVE-2016-1838 | `libxml2-2.9.2-libxml2-gcc-O0` | absent | error |
| not_affected_FN | CVE-2016-1838 | `libxml2-2.9.4-libxml2-gcc-O0` | not_affected | present |
| error | CVE-2019-19956 | `libxml2-2.9.9-rc1-libxml2-gcc-O0` | absent | error |
| error | CVE-2023-28484 | `libxml2-2.11.1-libxml2-gcc-O0` | present | error |

### imagemagick-10 / pptagent / deepseek-v4-flash no-thinking

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| FP | CVE-2016-5689 | `imagemagick-7.0.1-4-magickcore-gcc-O0` | absent | present |
| inconclusive | CVE-2016-5689 | `imagemagick-7.0.1-6-magickcore-gcc-O0` | absent | inconclusive |
| inconclusive | CVE-2017-11523 | `imagemagick-7.0.5-8-magickcore-gcc-O0` | absent | inconclusive |
| FN | CVE-2017-11523 | `imagemagick-7.0.6-3-magickcore-gcc-O0` | present | absent |
| FN | CVE-2017-11523 | `imagemagick-7.0.6-4-magickcore-gcc-O0` | present | absent |
| error | CVE-2019-10131 | `imagemagick-7.0.7-25-magickcore-gcc-O0` | absent | error |
| FP | CVE-2019-10131 | `imagemagick-7.0.7-27-magickcore-gcc-O0` | absent | present |
| FN | CVE-2019-10131 | `imagemagick-7.1.0-0-magickcore-gcc-O0` | present | absent |
| not_affected_FN | CVE-2019-17541 | `imagemagick-7.0.8-52-magickcore-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2019-17541 | `imagemagick-7.0.8-53-magickcore-gcc-O0` | not_affected | present |
| error | CVE-2023-34153 | `imagemagick-7.1.0-0-magickcore-gcc-O0` | absent | error |

### imagemagick-10 / codex exec / GPT default

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| inconclusive | CVE-2015-8895 | `imagemagick-7.0.5-1-magickcore-gcc-O0` | present | inconclusive |
| FP | CVE-2016-5689 | `imagemagick-7.0.1-4-magickcore-gcc-O0` | absent | present |
| FP | CVE-2016-5689 | `imagemagick-7.0.1-5-magickcore-gcc-O0` | absent | present |
| FP | CVE-2016-5689 | `imagemagick-7.0.1-6-magickcore-gcc-O0` | absent | present |
| inconclusive | CVE-2017-11523 | `imagemagick-7.0.5-7-magickcore-gcc-O0` | absent | inconclusive |
| FP | CVE-2017-11523 | `imagemagick-7.0.5-8-magickcore-gcc-O0` | absent | present |
| FP | CVE-2019-10131 | `imagemagick-7.0.7-26-magickcore-gcc-O0` | absent | present |
| FN | CVE-2019-10131 | `imagemagick-7.1.0-0-magickcore-gcc-O0` | present | absent |
| not_affected_FN | CVE-2019-17541 | `imagemagick-7.0.8-52-magickcore-gcc-O0` | not_affected | present |
| not_affected_FN | CVE-2019-17541 | `imagemagick-7.0.8-53-magickcore-gcc-O0` | not_affected | present |
| FN | CVE-2019-17541 | `imagemagick-7.1.0-1-magickcore-gcc-O0` | present | absent |
| FN | CVE-2019-17541 | `imagemagick-7.1.0-2-magickcore-gcc-O0` | present | absent |
| FP | CVE-2023-34153 | `imagemagick-7.1.0-0-magickcore-gcc-O0` | absent | present |
| FN | CVE-2023-34153 | `imagemagick-7.1.0-1-magickcore-gcc-O0` | present | absent |

### imagemagick-10 / codex exec / deepseek-v4-flash no-thinking

| kind | CVE | binary | expected | predicted |
| --- | --- | --- | --- | --- |
| FP | CVE-2016-5689 | `imagemagick-7.0.1-4-magickcore-gcc-O0` | absent | present |
| FP | CVE-2016-5689 | `imagemagick-7.0.1-5-magickcore-gcc-O0` | absent | present |
| error | CVE-2016-5689 | `imagemagick-7.0.1-6-magickcore-gcc-O0` | absent | error |
| FP | CVE-2017-11523 | `imagemagick-7.0.5-7-magickcore-gcc-O0` | absent | present |
| FP | CVE-2017-15277 | `imagemagick-7.0.6-1-magickcore-gcc-O0` | absent | present |
| FN | CVE-2017-15277 | `imagemagick-7.0.6-4-magickcore-gcc-O0` | present | absent |
| FP | CVE-2019-10131 | `imagemagick-7.0.7-25-magickcore-gcc-O0` | absent | present |
| FP | CVE-2019-10131 | `imagemagick-7.0.7-26-magickcore-gcc-O0` | absent | present |
| FP | CVE-2019-10131 | `imagemagick-7.0.7-27-magickcore-gcc-O0` | absent | present |
| not_affected_FN | CVE-2019-17541 | `imagemagick-7.0.8-52-magickcore-gcc-O0` | not_affected | absent |
| not_affected_FN | CVE-2019-17541 | `imagemagick-7.0.8-53-magickcore-gcc-O0` | not_affected | present |
| FP | CVE-2019-17541 | `imagemagick-7.0.8-54-magickcore-gcc-O0` | absent | present |
| FN | CVE-2019-17541 | `imagemagick-7.1.0-2-magickcore-gcc-O0` | present | absent |
| FP | CVE-2023-34153 | `imagemagick-7.1.0-0-magickcore-gcc-O0` | absent | present |
| FN | CVE-2023-34153 | `imagemagick-7.1.0-1-magickcore-gcc-O0` | present | absent |

## Notes

- `DSR_binary` 是仅针对 present/absent patch-presence 的 decisive success rate；`total DSR` 把 not_affected 纳入总体正确率/DSR。
- `notaffected` 是预测为 not_affected 且正确的数量；不是 ground truth 中 not_affected 的总数。
- 旧 OpenSSL codex+dpsk run 没进入主表：它的 merged results 只有 1 个 CVE/4 个 testcase 且全是 wrapper error，不能代表完整配置。
