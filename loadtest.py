"""旁路采集器压测：验证记录层吞吐与延迟，纯标准库。

用法：
    python loadtest.py --url http://127.0.0.1:8088/ --n 5000 --c 32

说明：只压旁路采集器（记录层），不会触发 LLM 研判；用于确认高并发下
采集不丢包、延迟可控。测完可用 wc -l miss_traffic.jsonl 核对条数。
"""
import argparse
import statistics
import threading
import time
import urllib.error
import urllib.request

PAYLOADS = [
    "/?q=hello+world",
    "/?q=1+AND+sleep(5)",
    "/?file=../../etc/passwd",
    "/?q=%3Csvg+onload%3Dalert(1)%3E",
]


def _worker(url, n, out, idx):
    latencies = []
    errors = 0
    for i in range(n):
        target = url.rstrip("/") + PAYLOADS[(idx + i) % len(PAYLOADS)]
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(target, timeout=5) as resp:
                resp.read()
        except (urllib.error.URLError, TimeoutError):
            errors += 1
        latencies.append((time.perf_counter() - t0) * 1000)
    out[idx] = (latencies, errors)


def main():
    ap = argparse.ArgumentParser(description="旁路采集器压测")
    ap.add_argument("--url", default="http://127.0.0.1:8088/")
    ap.add_argument("--n", type=int, default=2000, help="每线程请求数")
    ap.add_argument("--c", type=int, default=20, help="并发线程数")
    args = ap.parse_args()

    out = [None] * args.c
    threads = [threading.Thread(target=_worker,
                                args=(args.url, args.n, out, i))
               for i in range(args.c)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0

    lat = [x for l, _ in out for x in l]
    errs = sum(e for _, e in out)
    lat.sort()
    total = len(lat)

    def pct(p):
        return lat[min(total - 1, int(total * p))] if total else 0

    print("requests=%d concurrency=%d elapsed=%.2fs qps=%.0f errors=%d" %
          (total, args.c, elapsed, total / elapsed if elapsed else 0, errs))
    print("latency ms: mean=%.1f p50=%.1f p95=%.1f p99=%.1f max=%.1f" %
          (statistics.mean(lat) if lat else 0, pct(0.5), pct(0.95),
           pct(0.99), lat[-1] if lat else 0))
    if errs:
        print("注意：存在失败请求，可能是采集器线程模型或文件写入竞争，需排查")


if __name__ == "__main__":
    main()
