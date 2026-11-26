#!/bin/sh
# AI-WAF 放行流量采集器（WSL 内）—— 由 start_all.bat 调用，请勿单独使用。

export MISS_COLLECTOR_HOST=0.0.0.0
export MISS_COLLECTOR_PORT=8088
export MISS_LOG_PATH="/mnt/c/Users/Administrator/AppData/Roaming/Trae CN/ModularData/ai-agent/work-mode-projects/6abe5daff4b8f86d5cbf9c24/aiwaf/miss_traffic.jsonl"
SCRIPT="/mnt/c/Users/Administrator/AppData/Roaming/Trae CN/ModularData/ai-agent/work-mode-projects/6abe5daff4b8f86d5cbf9c24/aiwaf/miss_collector.py"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[collector] python3 未安装"
    exit 1
fi

pkill -f miss_collector.py 2>/dev/null || true
sleep 0.3
nohup python3 "$SCRIPT" >/tmp/miss_collector.log 2>&1 &

# 冷启动（WSL 刚起来）时首次自测可能过早，重试最多 10 次
i=0
while [ $i -lt 10 ]; do
    if curl -sf -m 2 -o /dev/null http://127.0.0.1:8088/selftest; then
        echo "[collector] listening 0.0.0.0:8088"
        exit 0
    fi
    i=$((i + 1))
    sleep 0.5
done

echo "[collector] 启动失败，日志末尾："
tail -5 /tmp/miss_collector.log 2>/dev/null
exit 1
