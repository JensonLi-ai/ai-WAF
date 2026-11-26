"""从公开语料库抽取攻击样本，生成统一的 JSONL 评测语料。

来源：
- SecLists (MIT): https://github.com/danielmiessler/SecLists
- PayloadsAllTheThings (MIT): https://github.com/swisskyrepo/PayloadsAllTheThings

用法：
    python tools/build_external_corpus.py
    python tools/build_external_corpus.py --proxy http://127.0.0.1:7897
    python tools/build_external_corpus.py --output corpus/external/attack_samples.jsonl

设计原则：
- 只做确定性的行级抽取，不调用 LLM；
- 每个来源按顺序等距采样，保证可复现；
- 用类别特征做粗筛，过滤说明文字、模板占位符和明显噪声；
- 每类最多 MAX_PER_CATEGORY 条，控制评测时长。
"""
import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

MAX_PER_CATEGORY = 10
MAX_PER_SOURCE = 10
MAX_LEN = 300
MIN_LEN = 3

SOURCES = [
    # SQL 注入
    {"cat": "sqli", "type": "lines", "cap": 4,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-SQLi.txt"},
    {"cat": "sqli", "type": "lines", "cap": 3,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/quick-SQLi.txt"},
    {"cat": "sqli", "type": "lines", "cap": 3,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt"},
    {"cat": "sqli", "type": "lines", "cap": 2,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt"},
    # XSS
    {"cat": "xss", "type": "lines", "cap": 4,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt"},
    {"cat": "xss", "type": "lines", "cap": 3,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Somdev.txt"},
    {"cat": "xss", "type": "lines", "cap": 3,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt"},
    # 命令注入
    {"cat": "cmdi", "type": "lines", "cap": 4,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt"},
    {"cat": "cmdi", "type": "lines", "cap": 6,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/UnixAttacks.fuzzdb.txt"},
    # 路径穿越
    {"cat": "traversal", "type": "lines", "cap": 5,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt"},
    {"cat": "traversal", "type": "lines", "cap": 5,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt"},
    # SSRF
    {"cat": "ssrf", "type": "markdown", "cap": 6,
     "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md"},
    # SSTI
    {"cat": "ssti", "type": "lines", "cap": 6,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/template-engines-expression.txt"},
    # XXE
    {"cat": "xxe", "type": "lines", "cap": 6,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XXE-Fuzzing.txt"},
    # 反序列化
    {"cat": "deser", "type": "markdown", "cap": 4,
     "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Deserialization/PHP.md"},
    {"cat": "deser", "type": "markdown", "cap": 3,
     "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Deserialization/Java.md"},
    {"cat": "deser", "type": "markdown", "cap": 3,
     "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Deserialization/Python.md"},
    # NoSQL
    {"cat": "nosql", "type": "lines", "cap": 6,
     "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/MongoDB.txt"},
    {"cat": "nosql", "type": "lines", "cap": 4,
     "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/NoSQL.txt"},
    # CRLF
    {"cat": "crlf", "type": "markdown", "cap": 6,
     "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/CRLF%20Injection/README.md"},
    # LDAP
    {"cat": "ldap", "type": "lines", "cap": 6,
     "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LDAP.Fuzzing.txt"},
    {"cat": "ldap", "type": "lines", "cap": 4,
     "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_FUZZ.txt"},
    {"cat": "jndi", "type": "markdown", "cap": 6,
     "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/CVE%20Exploits/Log4Shell.md"},
]

MARKERS = {
    "sqli": re.compile(
        r"(?is)(union\s+(?:all\s+)?select|information_schema|"
        r"\b(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay|"
        r"'\s*(?:or|and)\b|'\s*(?:--|#)|"
        r"\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)"),
    "xss": re.compile(
        r"(?is)(<script|on(?:error|load|focus|mouseover|click)\s*=|"
        r"javascript\s*:|<svg|<img[^>]+on|alert\s*\(|prompt\s*\(|"
        r"document\.cookie|<iframe|data:text/html)"),
    "cmdi": re.compile(
        r"(?is)([|;&]\s*(?:id|whoami|cat|ls|pwd|sh|bash|ping|wget|curl|nc|uname)\b|"
        r"\$\([^)]*\)|`[^`]+`|&&\s*\w+|%0a\s*(?:id|cat|ls)|/bin/(?:ba)?sh)"),
    "traversal": re.compile(
        r"(?is)(\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.%2f|%c0%af|\.\.;/)"),
    "ssrf": re.compile(
        r"(?is)(https?://|gopher://|file://|dict://|ldap://|ftp://|"
        r"169\.254\.169\.254|127\.0\.0\.1|\[::1\]|0x7f000001|"
        r"2130706433|localtest\.me|metadata)"),
    "ssti": re.compile(r"(\$\{|\#\{|\{\{|@\{|<%[=#]?|\{\{=)"),
    "xxe": re.compile(r"(?is)(<!ENTITY|<!DOCTYPE|SYSTEM\s+[\"'])"),
    "deser": re.compile(
        r"(?is)(^O:\d+:\"|^rO0AB|^aced00|^cos\\nsystem|"
        r"^c__builtin__|^\\x80\\x04\\x95)"),
    "nosql": re.compile(r"(\$ne|\$gt|\$where|\$regex|\$or|\$and|\[\$)"),
    "crlf": re.compile(r"(?is)(%0d%0a|%0aSet-Cookie|%0d%0aLocation|\\r\\n|%E5%98%8A)"),
    "ldap": re.compile(r"(\*\)\(\||\(\|\(|\*\)\(uid=|objectclass=\*|"
                       r"%2A%28%7C|uid=\*|%2A%7C)"),
    "jndi": re.compile(r"(?is)(\$\{jndi:)"),
}

NOISE_RE = re.compile(
    r"(?is)(__TIME__|\[DELIMITER\]|<PAYLOAD>|\bTODO\b|\bEXAMPLE\b|"
    r"^\s*(?:#|//|<!--|/\*|\*|Note:|Warning:|Example:|The |This |Use |"
    r"If |You |For |A |An )|"
    r"^(?:java|python|python3|import|from|pip|git|docker|curl|wget|cd|"
    r"sudo|npm|node|apt|brew)\s|"
    r"^\s*Mapping\s|\s=\shttps?://|"
    r"^\s*\|.*\|\s*$|"
    r"^\s*[-=]{3,}\s*$)")
FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.S)


def normalize(cat, s):
    """把少数包装形式还原成纯 payload（目前只处理 PHP 反序列化示例）。"""
    s = s.strip()
    if cat == "deser":
        m = re.match(r'^string\(\d+\)\s+"(O:\d+:.*)"$', s)
        if m:
            return m.group(1)
    return s


def fetch(url, proxy=None):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "aiwaf-corpus-builder"})
    with opener.open(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")


def extract_lines(text, kind):
    if kind == "markdown":
        lines = []
        for block in FENCE_RE.findall(text):
            lines.extend(block.splitlines())
        return lines
    return text.splitlines()


def keep(cat, s):
    s = s.strip()
    if not (MIN_LEN <= len(s) <= MAX_LEN):
        return False
    if NOISE_RE.search(s):
        return False
    if "\x00" in s:
        return False
    if not MARKERS[cat].search(s):
        return False
    # 过滤明显的整段说明/请求模板
    if s.count(" ") > 14 and not re.search(r"[<>${}()'\";|&`]", s):
        return False
    return True


def pick(cands, cap):
    if len(cands) <= cap:
        return cands
    step = len(cands) / float(cap)
    return [cands[min(len(cands) - 1, int(i * step))] for i in range(cap)]


def main(argv=None):
    ap = argparse.ArgumentParser(description="构建外部攻击语料")
    ap.add_argument("--output", default="corpus/external/attack_samples.jsonl")
    ap.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY")
                    or os.environ.get("https_proxy"))
    args = ap.parse_args(argv)

    by_cat = {}
    seen = set()
    for src in SOURCES:
        cat = src["cat"]
        try:
            text = fetch(src["url"], args.proxy)
        except Exception as e:
            print("[skip] %s: %s" % (src["url"], e), file=sys.stderr)
            continue
        cands = []
        for raw in extract_lines(text, src["type"]):
            s = normalize(cat, raw)
            if not keep(cat, s):
                continue
            key = s.lower()
            if key in seen:
                continue
            seen.add(key)
            cands.append(s)
        chosen = pick(cands, min(src["cap"], MAX_PER_SOURCE))
        if chosen:
            by_cat.setdefault(cat, []).extend(chosen)
            print("[ok] %-10s +%d  %s" % (cat, len(chosen), src["url"].split("/")[-1]))

    order = ["sqli", "xss", "cmdi", "traversal", "ssrf", "ssti",
             "xxe", "deser", "nosql", "crlf", "ldap", "jndi"]
    out = []
    for cat in order:
        payloads = by_cat.get(cat, [])
        payloads = pick(payloads, MAX_PER_CATEGORY)
        for i, p in enumerate(payloads, 1):
            out.append({"category": cat, "name": "ext-%s-%02d" % (cat, i),
                        "payload": p, "source": "external"})

    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in out:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print("\n总计 %d 条 -> %s" % (len(out), path))
    for cat in order:
        print("  %-10s %d" % (cat, sum(1 for r in out if r["category"] == cat)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
