cd /home/zhangxb/ClawSpace/agent/straight_detect && \
python3 codex_patch_presence_batch.py \
  --project-json /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.behavior.json \
  --testset-json /home/zhangxb/ClawSpace/agent/straight_detect/datasets/curl_dataset4ppt_20/testset.json \
  --target-dir /home/zhangxb/extdisk/dataset4ppt/curl/binaries/target/curl_stripped \
  --groundtruth-json /home/zhangxb/ClawSpace/agent/straight_detect/datasets/curl_dataset4ppt_20/groundtruth.json \
  --opt o0 \
  --output /home/zhangxb/ClawSpace/agent/straight_detect/runs/curl20_binarywise_stripped_dpsk_flash_off_results.json \
  --raw-dir /home/zhangxb/ClawSpace/agent/straight_detect/runs/curl20_binarywise_stripped_dpsk_flash_off_raw \
  --prompt-template /home/zhangxb/ClawSpace/agent/straight_detect/prompts/patch_presence_stripped_unbounded.md \
  --binarywise \
  --provider dpsk \
  --dpsk-base-url http://127.0.0.1:18080/v1 \
  --dpsk-model deepseek-v4-flash \
  --codex-json-events \
  --timeout 3600
