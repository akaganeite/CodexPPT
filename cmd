cd /home/zhangxb/ClawSpace/agent/straight_detect && \
python3 codex_patch_presence_batch.py \
  --project-json /home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.behavior.json \
  --testset-json /home/zhangxb/ClawSpace/agent/straight_detect/testset/curl.json \
  --target-dir /home/zhangxb/ClawSpace/agent/straight_detect/curl/gcc_stripped \
  --groundtruth-json /home/zhangxb/ClawSpace/agent/straight_detect/groundtruth/curl.json \
  --opt o0 \
  --output /home/zhangxb/ClawSpace/agent/straight_detect/runs/curl_stripped_o0_unbounded_json_events_results.json \
  --raw-dir /home/zhangxb/ClawSpace/agent/straight_detect/runs/curl_stripped_o0_unbounded_json_events_raw \
  --prompt-template /home/zhangxb/ClawSpace/agent/straight_detect/prompts/patch_presence_stripped_unbounded.md \
  --codex-json-events \
  --timeout 3600