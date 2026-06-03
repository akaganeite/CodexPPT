# Curl DPSK anon/redacted retry set

Source run:
`/home/zhangxb/ClawSpace/agent/agenticdetect/runs/curl_stripped_o0_dpsk_behavior_minified_anon_redacted`

## Error

| CVE | Category | Note |
| --- | --- | --- |
| CVE-2018-16842 | error | Model produced final natural-language analysis but did not call `submit_cve_detection_results`; candidate for forced-submit retry. |

## Inconclusive

| CVE | Category | Note |
| --- | --- | --- |
| CVE-2017-2629 | inconclusive | Could not reliably locate `allocate_conn` / SSL config copy evidence in stripped binaries. |
| CVE-2017-8816 | inconclusive | Could not positively locate `Curl_ntlm_core_mk_ntlmv2_hash`. |
| CVE-2018-16840 | inconclusive | Could not locate `Curl_close` and verify `data->multi_easy = NULL`. |
| CVE-2020-8284 | inconclusive | Could not verify `config_init` / `ftp_skip_ip` default initialization due layout uncertainty. |

## Mismatch

| CVE | Category | Note |
| --- | --- | --- |
| CVE-2016-8623 | mismatch | FN cases: patched versions predicted `absent`. |
| CVE-2016-9594 | mismatch | FP cases: vulnerable versions predicted `present`. |
| CVE-2017-1000101 | mismatch | FP case: vulnerable version predicted `present`. |
| CVE-2017-8817 | mismatch | FN cases: patched versions predicted `absent`. |
| CVE-2017-8818 | mismatch | FN cases: patched versions predicted `absent`. |
| CVE-2020-8169 | mismatch | FN cases: patched versions predicted `absent`. |
| CVE-2022-42916 | mismatch | FN cases: patched versions predicted `absent`. |
| CVE-2013-1944 | mismatch | Remaining FN case after anon/redacted rerun. |
