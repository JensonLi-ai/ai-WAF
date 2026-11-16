#!/bin/sh
# 在 WSL 内启动放行流量采集器（tengine 是 host 网络，upstream 127.0.0.1:8088）
export MISS_COLLECTOR_HOST=0.0.0.0
export MISS_COLLECTOR_PORT=8088
export MISS_LOG_PATH="/mnt/c/Users/Administrator/AppData/Roaming/Trae CN/ModularData/ai-agent/work-mode-projects/6abe5daff4b8f86d5cbf9c24/aiwaf/miss_traffic.jsonl"
pkill -f miss_collector.py 2>/dev/null
sleep 0.3
SCRIPT="/mnt/c/Users/Administrator/AppData/Roaming/Trae CN/ModularData/ai-agent/work-mode-projects/6abe5daff4b8f86d5cbf9c24/aiwaf/miss_collector.py"
nohup python3 "$SCRIPT" >/tmp/miss_collector.log 2>&1 &
sleep 0.8
cat /tmp/miss_collector.log
curl -s -m 2 -o /dev/null -w "self-test http=%{http_code}\n" http://127.0.0.1:8088/selftest