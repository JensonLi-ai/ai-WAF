"""放行流量记录后端：监听雷池 upstream 指向的端口，逐条写 JSONL。

为什么需要它：雷池社区版不记录「放行流量」，且 tengine 无 mirror 模块、
access_log 又被 t1k 拦截链路绕过（worker 不写）。本服务充当「真实业务后端」
——凡能到达这里的请求，就是雷池放行、未被拦截的流量（漏判候选），完整落盘
供引擎增量读取。

运行方式（两种，同一份代码）：
1. 作为 aiwaf 包：`python -m aiwaf.miss_collector`（main.py 会以线程启动）
2. 独立运行（如 WSL 内，绕开 Windows 防火墙/IP 漂移）：
     MISS_LOG_PATH=/mnt/c/.../miss_traffic.jsonl python3 /mnt/c/.../miss_collector.py
   tengine 是 host 网络，雷池 upstream 指向 127.0.0.1:8088 即命中本脚本回环。

独立运行时配置来源：环境变量 MISS_COLLECTOR_HOST / MISS_COLLECTOR_PORT /
MISS_LOG_PATH / MISS_MAX_BODY；作为包运行时用 aiwaf.config。
"""
import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from . import config
    _HOST = config.MISS_COLLECTOR_HOST
    _PORT = config.MISS_COLLECTOR_PORT
    _PATH = config.MISS_LOG_PATH
    _MAXBODY = config.MISS_MAX_BODY
except (ImportError, ValueError):
    _HOST = os.environ.get("MISS_COLLECTOR_HOST", "127.0.0.1")
    _PORT = int(os.environ.get("MISS_COLLECTOR_PORT", "8088"))
    _PATH = os.environ.get("MISS_LOG_PATH", "miss_traffic.jsonl")
    _MAXBODY = int(os.environ.get("MISS_MAX_BODY", "65536"))


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.0：响应后强制关闭连接，规避 HTTP/1.1 keepalive 状态机在
    # ThreadingHTTPServer 下与 tengine upstream 复用连接的兼容问题（曾致 504）。
    protocol_version = "HTTP/1.0"

    def _log_and_reply(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = ""
        if 0 < length <= _MAXBODY:
            body = self.rfile.read(length).decode("utf-8", "replace")
        elif length > _MAXBODY:
            body = "(body %d bytes, 超限截断)" % length
        rec = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": self.client_address[0],
            "method": self.command,
            "host": self.headers.get("Host", ""),
            "raw_uri": self.path,          # 原始 request-target（含 % 编码）
            "headers": dict(self.headers.items()),
            "body": body,
        }
        with open(_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        payload = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _log_and_reply
    do_HEAD = _log_and_reply

    def log_message(self, fmt, *args):
        pass  # 抑制 http.server 默认 stderr 日志


def serve():
    srv = ThreadingHTTPServer((_HOST, _PORT), _Handler)
    srv.daemon_threads = True
    print("[miss-collector] listening %s:%d -> %s" %
          (_HOST, _PORT, _PATH), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()