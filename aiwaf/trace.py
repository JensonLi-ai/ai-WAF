"""链路追踪：把一个请求走完「雷池 → 采集 → 粗筛 → LLM 研判 → 规则下发」
的全过程逐阶段打印到终端，用于直观观察拦截过程。

用法：
    python -m aiwaf.trace                        # 默认命令注入样本
    python -m aiwaf.trace --preset ssrf          # 换样本
    python -m aiwaf.trace --param id --payload "1' AND sleep(5)--"
    python -m aiwaf.trace --preset traversal --verify   # 下发规则后再打一次验证拦截

注意：该命令会真实经过雷池发请求，可能产生攻击日志、命中规则，并可能新增
一条 AI 观察期规则（与引擎在线时的行为一致）。
"""
import argparse
import json
import os
import re
import sys
import time

import urllib.error
import urllib.parse
import urllib.request

from . import config, db, engine, llm_client, safeline_api

PRESETS = {
    "cmdi":      ("cmd",  "|id"),
    "xss":       ("q",    "<svg onload=alert(1)>"),
    "sqli":      ("id",   "1' AND sleep(5)--"),
    "traversal": ("file", "../../etc/passwd"),
    "ssrf":      ("url",  "http://169.254.169.254/latest/meta-data/"),
    "ssti":      ("q",    "#{7*7}"),
    "phpser":    ("q",    'O:8:"stdClass":1:{}'),
    "benign":    ("v",    "hello world"),
}


class C:
    """ANSI 颜色；--no-color 时全部置空。"""

    CY = "\033[36m"
    GR = "\033[32m"
    RE = "\033[31m"
    YE = "\033[33m"
    DI = "\033[2m"
    BO = "\033[1m"
    Z = "\033[0m"


def _enable_ansi():
    """Windows 控制台默认不解析 ANSI，这里开启虚拟终端处理。"""
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _disable_color():
    for name in ("CY", "GR", "RE", "YE", "DI", "BO", "Z"):
        setattr(C, name, "")


_t0 = time.time()


def emit(mark, name, msg, color=None):
    """打印一个阶段行：[耗时] 标记 阶段名 内容。"""
    color = color or C.CY
    elapsed = (time.time() - _t0) * 1000
    print("%s[%6.0fms]%s %s%s%s %-10s%s %s" % (
        C.DI, elapsed, C.Z, color, mark, C.Z, name, C.Z, msg), flush=True)


def rule_line(char="─", n=88):
    print("%s%s%s" % (C.DI, char * n, C.Z), flush=True)


# ---------------- 发请求 ----------------

def send(base, host, target, timeout=10):
    """经雷池发一次请求，返回 (状态码, 响应片段, 耗时ms)。"""
    url = base.rstrip("/") + target
    req = urllib.request.Request(url, headers={
        "Host": host,
        "User-Agent": "AI-WAF-trace/1.0",
        "Accept": "*/*",
        "Connection": "close",
    })
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()[:160], (time.time() - t) * 1000
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:160], (time.time() - t) * 1000
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e), (time.time() - t) * 1000


# ---------------- 日志/采集 ----------------

def lookup_record(client, host, path, timeout_s=1.2):
    """在攻击日志里找刚被拦截的那条记录（按 host+路径，且时间在最近 3 分钟）。

    注意：AI 下发的自定义规则默认 log=false，命中它们不会落攻击日志，
    因此查不到记录属正常，需退回本地规则比对（见 lookup_policy_hit）。
    """
    deadline = time.time() + timeout_s
    while True:
        try:
            res = client.list_records(page=1, page_size=20)
        except Exception as e:
            return None, "拉取攻击日志失败: %s" % e
        now = time.time()
        for rec in (res.get("records") or []):
            if (rec.get("host") or "") != host:
                continue
            url_path = (rec.get("url_path") or "").split("?", 1)[0]
            if url_path != path.split("?", 1)[0]:
                continue
            created = rec.get("created_at") or rec.get("timestamp") or 0
            if created and abs(now - float(created)) > 180:
                continue
            return rec, None
        if time.time() >= deadline:
            return None, None
        time.sleep(0.4)


def lookup_policy_hit(client, host, target):
    """本地比对自定义规则，猜出本次请求被哪条规则拦下（自定义规则不落日志）。"""
    raw = target
    decoded = urllib.parse.unquote(target)
    try:
        policies = client.list_policies(page=1, page_size=100)
    except Exception:
        return None
    for pol in policies or []:
        if not pol.get("is_enabled", True):
            continue
        for group in (pol.get("pattern") or []):
            uri_rx = None
            host_ok = False
            for cond in group or []:
                k = cond.get("k")
                if k == "host":
                    host_ok = host in (cond.get("v") or [])
                elif k == "uri":
                    uri_rx = (cond.get("v") or [None])[0]
            if not host_ok or not uri_rx:
                continue
            try:
                if re.search(uri_rx, raw) or re.search(uri_rx, decoded):
                    return pol
            except re.error:
                continue
    return None


def find_miss_line(target, timeout_s=2.0):
    """在放行流量日志里找本次请求的记录，返回 (行号, 记录)。"""
    path = config.MISS_LOG_PATH
    deadline = time.time() + timeout_s
    while True:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return None, None
        for idx in range(len(lines) - 1, -1, -1):
            try:
                rec = json.loads(lines[idx])
            except Exception:
                continue
            if rec.get("raw_uri") == target:
                return idx + 1, rec
        if time.time() >= deadline:
            return None, None
        time.sleep(0.3)


# ---------------- 主流程 ----------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="AI-WAF 链路追踪（终端流式）")
    ap.add_argument("--preset", choices=sorted(PRESETS), default="cmdi",
                    help="内置样本（默认 cmdi）")
    ap.add_argument("--param", help="查询参数名（覆盖预设）")
    ap.add_argument("--payload", help="查询参数值原文（覆盖预设）")
    ap.add_argument("--host", default=os.environ.get("TRACE_HOST", "demo.test"))
    ap.add_argument("--url", default=os.environ.get("TRACE_URL",
                                                    "http://127.0.0.1:80"))
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--verify", action="store_true",
                    help="若本次下发了规则，再发一次同样请求验证是否被拦截")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        _disable_color()
    else:
        _enable_ansi()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    param, payload = PRESETS[args.preset]
    param = args.param or param
    payload = args.payload if args.payload is not None else payload
    target = "/?" + urllib.parse.urlencode(
        {param: payload}, quote_via=urllib.parse.quote)

    db.init()
    llm = llm_client.LlmClient()
    if config.SAFELINE_AUTH_MODE == "openapi" and config.SAFELINE_OPENAPI_TOKEN:
        safeline = safeline_api.OpenApiKeySafelineClient()
    else:
        safeline = safeline_api.JwtSafelineClient()
    eng = engine.Engine(safeline, llm)

    print("%sAI-WAF 链路追踪%s  目标 %s  Host %s" %
          (C.BO, C.Z, args.url, args.host))
    print("%s样本  %s = %s%s" % (C.DI, param, payload[:70], C.Z))
    rule_line()

    # ① 客户端
    emit("①", "客户端", "%s %s%s%s" % ("GET", C.CY, target, C.Z))

    # ② 雷池检测
    status, body, cost = send(args.url, args.host, target, args.timeout)

    if status == 403:
        emit("②", "雷池检测", "%sHTTP 403 → 拦截%s  (%.0fms)" %
             (C.RE, C.Z, cost), C.RE)
        rec, err = lookup_record(safeline, args.host, target)
        if rec:
            emit("③", "攻击日志",
                 "rule=%s module=%s reason=%s" % (
                     rec.get("short_rule_id") or rec.get("rule_id") or "-",
                     rec.get("module") or "-",
                     (rec.get("reason") or "-")[:28]),
                 C.GR)
        elif err:
            emit("③", "攻击日志", err, C.YE)
        else:
            pol = lookup_policy_hit(safeline, args.host, target)
            if pol:
                uri_rx = ""
                for group in (pol.get("pattern") or []):
                    for cond in group or []:
                        if cond.get("k") == "uri":
                            uri_rx = (cond.get("v") or [""])[0]
                emit("③", "规则归属",
                     "%spolicy %s%s  %s" % (C.GR, pol.get("id"), C.Z,
                                            pol.get("name") or ""), C.GR)
                emit("", "", "uri 正则 %s%s%s（自定义规则 log=false，不落攻击日志）" %
                     (C.DI, uri_rx, C.Z), C.DI)
            else:
                emit("③", "规则归属",
                     "未落攻击日志，本地未匹配到自定义规则（可能为内置语义引擎拦截）",
                     C.DI)
        rule_line()
        emit("✔", "结论", "%s已拦截%s：请求在雷池被阻断，未到达后端，未进入漏判管线" %
             (C.RE + C.BO, C.Z), C.RE)
        return 0

    if status is None:
        emit("②", "雷池检测", "%s连接失败%s %s" % (C.RE, C.Z, body), C.RE)
        rule_line()
        emit("✘", "结论", "无法连通雷池入口，请检查 tengine 与 %s" % args.url, C.RE)
        return 1

    if not (200 <= status < 400):
        emit("②", "雷池检测", "%sHTTP %s → 非放行非拦截%s（人机验证/限流/后端异常）" %
             (C.YE, status, C.Z), C.YE)
        if status == 465:
            emit("", "", "雷池下发人机验证（sl-antibot: waiting），请求被挂起未到后端",
                 C.DI)
        rule_line()
        emit("✘", "结论", "本次观测不到拦截/放行结果，请稍后重试或调整该站点防护策略",
             C.YE)
        return 1

    emit("②", "雷池检测", "%sHTTP %s → 放行%s  (%.0fms)" %
         (C.YE, status, C.Z, cost), C.YE)

    # ③ 旁路采集
    lineno, miss_rec = find_miss_line(target)
    if not miss_rec:
        emit("③", "旁路采集", "未在 %s 找到该请求" %
             os.path.basename(config.MISS_LOG_PATH), C.RE)
        emit("", "", "提示：采集器需在 WSL 内运行（tengine 是 host 网络，"
             "upstream 为 127.0.0.1:8088）", C.DI)
        rule_line()
        emit("✘", "结论", "请求被放行但未落采集日志，无法研判（检查 miss-collector）",
             C.RE)
        return 1
    emit("③", "旁路采集", "%s 第 %d 行  src_ip=%s" %
         (os.path.basename(config.MISS_LOG_PATH), lineno,
          miss_rec.get("src_ip") or "-"), C.GR)

    raw_uri = miss_rec.get("raw_uri") or target
    uri = urllib.parse.unquote(raw_uri)

    # ④ 粗筛
    hit = engine.MISS_SUSPECT_RE.search(uri)
    if not hit:
        emit("④", "粗筛", "MISS_SUSPECT_RE 未命中 → 判为正常流量", C.GR)
        db.add_normal(uri, host=miss_rec.get("host") or args.host, uri=uri,
                      src_ip=miss_rec.get("src_ip") or "")
        rule_line()
        emit("✔", "结论", "干净流量，不调用 LLM，不产生规则", C.GR)
        return 0
    emit("④", "粗筛", "命中 %s%-28s%s → 送 LLM 研判" %
         (C.YE, repr(hit.group(0))[:28], C.Z), C.YE)

    # ⑤ LLM 研判
    query = uri.split("?", 1)[1] if "?" in uri else uri
    ev = {"host": miss_rec.get("host") or args.host, "uri": uri,
          "payload": query or uri, "src_ip": miss_rec.get("src_ip") or ""}
    t_llm = time.time()
    try:
        a = llm.analyze(ev)
    except Exception as e:
        emit("⑤", "LLM 研判", "调用失败: %s" % e, C.RE)
        rule_line()
        emit("✘", "结论", "LLM 不可用，本次无法研判", C.RE)
        return 1
    llm_ms = (time.time() - t_llm) * 1000
    vcolor = {"attack": C.RE, "benign": C.GR}.get(a["verdict"], C.YE)
    emit("⑤", "LLM 研判", "%s%s %s%.2f%s %s  (%.0fms)" % (
        vcolor, a["verdict"], C.DI, a["confidence"], C.Z,
        ("/" + a["variant"]) if a.get("variant") else "", llm_ms), vcolor)
    print("%s            %s%s%s" % (C.DI, a.get("explain", "")[:78], C.Z,
                                    ""), flush=True)

    if a["verdict"] != "attack" or a["confidence"] < config.MIN_CONFIDENCE:
        if a["verdict"] == "benign":
            db.add_normal(uri, host=miss_rec.get("host") or args.host,
                          uri=uri, src_ip=miss_rec.get("src_ip") or "")
        rule_line()
        emit("✔", "结论", "判为非攻击或置信度不足（阈值 %.2f），不下发规则" %
             config.MIN_CONFIDENCE, C.GR)
        return 0

    # ⑥ 特指性校验
    regex = (a.get("suggested_rule") or "").strip()
    if not regex:
        emit("⑥", "特指性校验", "模型未给出规则", C.YE)
        rule_line()
        emit("✔", "结论", "攻击判定成立但无可用规则，仅记录研判结果", C.YE)
        return 0
    ok, why = engine._regex_specific_enough(regex)
    if ok:
        emit("⑥", "特指性校验", "%s✔ 通过%s（%s）  %s" %
             (C.GR, C.Z, why, regex), C.GR)
    else:
        emit("⑥", "特指性校验", "%s✘ 过泛%s（%s）" % (C.RE, C.Z, why), C.RE)
        rule_line()
        emit("✔", "结论", "%sAI 主动放弃下发规则%s：规则过泛，转正后易误杀正常业务" %
             (C.YE, C.Z), C.YE)
        return 0

    # ⑦ 规则下发
    before = {r.get("safeline_policy_id") for r in db.all_rules()}
    row = {"host": miss_rec.get("host") or args.host,
           "uri": uri, "payload": query or uri}
    eng._maybe_create_rule(row, a)
    after = {r.get("safeline_policy_id") for r in db.all_rules()}
    new_ids = after - before

    rule_line()
    covered = None
    if new_ids:
        new_rule = next((r for r in db.all_rules()
                         if r.get("safeline_policy_id") in new_ids), {})
        emit("⑦", "规则下发", "%spolicy %s 已创建%s  %s" % (
            C.GR, sorted(x for x in new_ids if x), C.Z,
            new_rule.get("name", "")), C.GR)
        emit("", "", "状态 %s  观察期至 %s" %
             (new_rule.get("status", "-"),
              new_rule.get("observed_until", "-")), C.DI)
        emit("✔", "结论", "%s新规则已下发%s，后续命中该特征的请求将被拦截" %
             (C.GR + C.BO, C.Z), C.GR)
        covered = True
    else:
        covered = next((r for r in db.all_rules()
                        if r.get("status") in ("observing", "promoted")
                        and r.get("regex") == regex), None)
        if covered:
            emit("⑦", "规则下发", "已存在等价规则 policy %s  %s（跳过重复创建）" %
                 (covered.get("safeline_policy_id"), covered.get("name", "")),
                 C.GR)
            emit("✔", "结论", "该攻击特征已有规则覆盖，无需重复下发", C.GR)
        else:
            emit("✘", "结论", "规则未下发（看上一行 skip 原因：样本不匹配/无站点绑定等）",
                 C.YE)

    # 可选：再打一次验证拦截
    if args.verify and covered:
        print()
        emit("⟳", "验证", "等待规则生效后重放同一请求…", C.DI)
        time.sleep(1.2)
        st2, _, cost2 = send(args.url, args.host, target, args.timeout)
        if st2 == 403:
            emit("✔", "验证", "%sHTTP 403 → 已被规则拦截%s  (%.0fms)" %
                 (C.RE + C.BO, C.Z, cost2), C.RE)
        else:
            emit("…", "验证", "HTTP %s → 仍放行（规则可能需热加载，或仅观察不拦截）" %
                 st2, C.YE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
