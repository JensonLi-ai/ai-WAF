#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI-WAF 全量攻击测试 —— 系统性打雷池 demo.test，统计拦截/漏判"""
import urllib.request, urllib.parse, urllib.error

TARGET = "http://127.0.0.1:80"
HOST = "demo.test"

def probe(params_path, qs):
    """params_path: URL路径; qs: 完整query字符串(原样拼)"""
    url = TARGET + params_path
    if qs:
        url += "?" + qs
    req = urllib.request.Request(url, headers={"Host": HOST, "User-Agent": "Mozilla/5.0 attack-suite"})
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return "ERR"

def q(param, payload):
    """参数名=quote(payload)"""
    return param + "=" + urllib.parse.quote(payload, safe='')

# (类别, 名称, query字符串)
TESTS = [
    # ---- SQL 注入 ----
    ("SQLi", "OR 恒真",            q("id", "1' OR '1'='1")),
    ("SQLi", "UNION SELECT",       q("id", "1 UNION SELECT username,password FROM users")),
    ("SQLi", "注释截断 --",         q("id", "1'--")),
    ("SQLi", "注释截断 #",          q("id", "1'#")),
    ("SQLi", "大小写绕过 Or",       q("id", "1' Or '1'='1")),
    ("SQLi", "内联注释绕过",        q("id", "1' UNION/**/SELECT/**/password/**/FROM/**/users--")),
    ("SQLi", "布尔盲注 AND 1=1",    q("id", "1' AND '1'='1")),
    ("SQLi", "时间盲注 SLEEP",      q("id", "1' AND SLEEP(5)--")),
    ("SQLi", "报错注入 extractvalue", q("id", "1' AND extractvalue(1,concat(0x7e,database()))--")),
    ("SQLi", "双URL编码绕过",       "id=1%2527%2520OR%25201%253D1"),
    ("SQLi", "宽字节注入 %df",      "id=%df%27 OR 1=1--"),

    # ---- XSS ----
    ("XSS", "script 标签",         q("q", "<script>alert(1)</script>")),
    ("XSS", "img onerror",         q("q", "<img src=x onerror=alert(1)>")),
    ("XSS", "svg onload",          q("q", "<svg onload=alert(1)>")),
    ("XSS", "body onload",         q("q", "<body onload=alert(1)>")),
    ("XSS", "iframe 嵌入",         q("q", "<iframe src=javascript:alert(1)>")),
    ("XSS", "javascript: 协议",    q("q", "javascript:alert(1)")),
    ("XSS", "大小写混合 ScRiPt",   q("q", "<ScRiPt>alert(1)</sCrIpT>")),
    ("XSS", "编码绕过 %3Cscript%3E", "q=%3Cscript%3Ealert(1)%3C/script%3E"),
    ("XSS", "事件 onmouseover",    q("q", "x\" onmouseover=alert(1)")),

    # ---- 命令注入 ----
    ("CMDi", "分号 ;",             q("cmd", ";cat /etc/passwd")),
    ("CMDi", "管道 |",             q("cmd", "|id")),
    ("CMDi", "反引号 `",           q("cmd", "`whoami`")),
    ("CMDi", "子shell $()",        q("cmd", "$(id)")),
    ("CMDi", "逻辑与 &&",          q("cmd", "&& id")),
    ("CMDi", "逻辑或 ||",          q("cmd", "|| id")),
    ("CMDi", "换行注入 %0a",       "cmd=%0aid"),
    ("CMDi", "大小写绕过 CAT",     q("cmd", ";CAT /etc/passwd")),
    ("CMDi", "管道强化 whoami",    q("cmd", "|whoami")),

    # ---- 路径穿越 ----
    ("Traversal", "相对路径 ../",   q("file", "../../../../etc/passwd")),
    ("Traversal", "编码 %2e%2e%2f", "file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("Traversal", "双写 ....//",   q("file", "....//....//etc/passwd")),
    ("Traversal", "绝对路径",       q("file", "/etc/passwd")),
    ("Traversal", "空字节 %00",     "file=../../../../etc/passwd%00.jpg"),

    # ---- SSRF ----
    ("SSRF", "云元数据 169.254",    q("url", "http://169.254.169.254/latest/meta-data/")),
    ("SSRF", "内网探测 127.0.0.1",  q("url", "http://127.0.0.1:22")),
    ("SSRF", "file 协议",          q("url", "file:///etc/passwd")),

    # ---- XXE ----
    ("XXE", "外部实体注入",        q("xml", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>")),

    # ---- SSTI 模板注入 ----
    ("SSTI", "Jinja2 {{7*7}}",     q("name", "{{7*7}}")),
    ("SSTI", "EL ${7*7}",          q("name", "${7*7}")),
    ("SSTI", "ERB <%=7*7%>",       q("name", "<%= 7*7 %>")),

    # ---- LDAP 注入 ----
    ("LDAP", "LDAP 注入",          q("user", "*)(uid=*))(|(uid=*")),

    # ---- CRLF 注入 ----
    ("CRLF", "CRLF 响应头",        "x=1%0d%0aSet-Cookie:evil=1"),

    # ---- WebShell / 代码上传 ----
    ("Shell", "PHP 一句话",        q("php", "<?php system($_GET[c]);?>")),
    ("Shell", "eval 执行",         q("c", "eval(base64_decode('cGhwaW5mbygpOw=='))")),

    # ---- 反序列化 ----
    ("Deser", "Java 序列化对象",   q("obj", "O:8:\"stdClass\":1:{s:1:\"x\";s:1:\"y\";}")),
]

def main():
    print("=" * 60)
    print("AI-WAF 全量攻击测试  (目标: demo.test 经雷池)")
    print("403=拦截  502/200=漏判透传  其他=见状态码")
    print("=" * 60)
    from collections import defaultdict
    stats = defaultdict(lambda: [0, 0])   # cat -> [拦截, 漏判]
    rows = []
    for cat, name, qs in TESTS:
        code = probe("/", qs)
        blocked = (code == 403)
        if blocked:
            stats[cat][0] += 1
            tag = "拦截"
        else:
            stats[cat][1] += 1
            tag = "漏判"
        rows.append((cat, name, code, tag))
    # 按类别打印
    last_cat = None
    for cat, name, code, tag in rows:
        if cat != last_cat:
            print("\n[%s]" % cat)
            last_cat = cat
        print("  %-26s -> %s  %s" % (name, code, tag))
    # 汇总
    print("\n" + "=" * 60)
    total_b = sum(v[0] for v in stats.values())
    total_m = sum(v[1] for v in stats.values())
    total = total_b + total_m
    print("合计: %d 个用例 | 拦截 %d | 漏判 %d | 拦截率 %.0f%%" % (total, total_b, total_m, 100.0*total_b/total))
    print("\n漏判清单:")
    for cat, name, code, tag in rows:
        if tag == "漏判":
            print("  - [%s] %s  (%s)" % (cat, name, code))
    print("=" * 60)

if __name__ == "__main__":
    main()