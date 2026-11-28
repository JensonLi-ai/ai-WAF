"""攻击家族聚类离线原型。

目的：验证「一请求一规则」是否可以升级为「一家族一规则」。
做法：
1. 用解码后的语法特征把样本归入攻击家族（时间盲注、SSTI、穿越、SSRF…）
2. 每个家族只用前面的样本（train）生成一条家族规则
3. 用最后一条没参与生成的同族样本（test）测泛化
4. 同时对比「从单条 train 样本提炼的字面/锚点规则」在 test 上的覆盖

运行：python -m aiwaf.family
"""
import re
from collections import defaultdict
from urllib.parse import unquote

from .benchmark import (ATTACK_SAMPLES, INJECTION_NORMAL, INJECTION_SAMPLES,
                        NORMAL_SAMPLES, load_external_attacks)
from .engine import _anchor_rule, _literal_rule, _regex_specific_enough

# 家族签名：按顺序匹配，先匹配到的家族优先。
# 这些是「家族级」语法，不是单条 payload 的字面规则。
FAMILY_SIGNATURES = {
    "time_based": r"(?i)(?:[;|]\s*|\b(?:and|or)\s+)(?:sleep|benchmark|pg_sleep)\b|"
                  r"\bwaitfor\s+delay\b|\b(?:pg_sleep|benchmark)\s*\(",
    "sqli_union": r"(?is)\bunion\s*(?:/\*.*?\*/\s*)*(?:all\s+)?select\b",
    "sqli_meta": r"(?i)information_schema",
    "sqli_stacked": r"(?i);\s*(?:drop|truncate|alter|delete|insert|update)\b",
    "sqli_oob": r"(?i)\bxp_(?:cmdshell|dirtree|fileexist|subdirs)\b",
    "sqli_tautology": r"(?i)(?:['\"]\s*(?:or|and)\b)|(?:\bor\s+\d+\s*=\s*\d+)",
    "sqli_comment": r"(?i)['\"]\s*(?:--|#)",
    "ssti": r"(?:\#\{|\$\{|@\{|\{\{|#set\s*\(|<%[=#]?)",
    "traversal": r"(?i)(?:\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.;/|%c0%af|%c1%9c|%00)",
    "ssrf": r"(?i)(?:127\.\d+\.\d+\.\d+|169\.254\.169\.254|2130706433|"
            r"0x7f[0-9a-f]+|\[::1\]|::1|localhost|localtest\.me|0\.0\.0\.0|"
            r"file://|gopher://|dict://)",
    "cmdi": r"(?i)(?:[;|]\s*(?:id|whoami|cat|ls|sh|bash|ping|wget|curl|nc)\b|"
            r"&&\s*(?:net|id|whoami|cat|ls|sh|bash)\b|"
            r"\$\([^)]*\)|`[^`]+`|/dev/tcp/|bash\s+-i\b|"
            r"%0[ad]\s*(?:id|whoami|cat|ls|sh|bash|wget|curl|nc)\b)",
    "deser": r"(?i)(?:aced00|rO0AB|O:\d+:|cos[\s\S]{0,4}system)",
    "nosql": r"(?i)(?:\[\$(?:ne|gt|gte|lt|lte|regex|where|exists|in|nin)\]|"
             r"\$(?:where|gt|gte|lt|lte|ne|regex|or|and)\s*[\"']?\s*:)",
    "ldap": r"(?:\*\)\(\w+=\*|\*\(\s*\||%2a%28%7c|\*\|)",
    "crlf": r"(?i)(?:%0d%0a|\r\n)(?:set-cookie|location|content-length)",
    "xss": r"(?i)(?:<script|<svg|\bon\w+\s*=|javascript:|data:text/html|"
           r"\b(?:alert|prompt|confirm)\s*\()",
    "xxe": r"(?i)<!ENTITY|<!DOCTYPE",
    "jndi": r"(?i)\$\{jndi:",
}


def decode_variants(payload):
    """返回原文 + 一次/二次解码结果（overlong 编码解码后会失真，需保留原文）。"""
    out = [payload or ""]
    p = payload or ""
    for _ in range(2):
        d = unquote(p)
        if d == p:
            break
        p = d
        if p not in out:
            out.append(p)
    return out


def family_of(category, payload):
    """返回攻击家族名；没有匹配到已知语法时返回 <category>:other。"""
    variants = decode_variants(payload)
    for fam, sig in FAMILY_SIGNATURES.items():
        if any(re.search(sig, p, re.I) for p in variants):
            return fam
    return "%s:other" % (category or "unknown")


def _matches(sig, payload):
    return any(re.search(sig, p, re.I) for p in decode_variants(payload))


def _base_matches(base, payload):
    return bool(base) and any(re.search(base, p)
                              for p in decode_variants(payload))


def evaluate():
    attacks = (ATTACK_SAMPLES + load_external_attacks() + INJECTION_SAMPLES)
    normals = ([p for _n, p in NORMAL_SAMPLES]
               + [p for _n, p in INJECTION_NORMAL])
    groups = defaultdict(list)
    for cat, name, payload in attacks:
        groups[family_of(cat, payload)].append((name, payload))

    rows = []
    total_train = total_test = 0
    fam_ok = fam_total = 0
    base_ok = base_total = 0
    for fam, sig in FAMILY_SIGNATURES.items():
        items = groups.get(fam) or []
        if len(items) < 2:
            if items:
                rows.append((fam, len(items), "-", "-", "-", "-", "样本不足"))
            continue
        train, test = items[:-1], items[-1:]
        train_cov = 100.0 * sum(_matches(sig, p) for _n, p in train) / len(train)
        test_cov = 100.0 * sum(_matches(sig, p) for _n, p in test) / len(test)
        base = (_anchor_rule(train[0][1])
                or _literal_rule({"payload": train[0][1]}))
        base_cov = 100.0 * sum(
            _base_matches(base, p) for _n, p in test
        ) / len(test)
        fp = sum(_matches(sig, p) for p in normals)
        spec = "Y" if _regex_specific_enough(sig)[0] else "N"
        rows.append((fam, len(items), train_cov, test_cov, base_cov, fp, spec))
        total_train += len(train)
        total_test += len(test)
        fam_ok += sum(_matches(sig, p) for _n, p in test)
        fam_total += len(test)
        base_ok += sum(_base_matches(base, p)
                       for _n, p in test)
        base_total += len(test)

    print("== 攻击家族聚类离线验证 ==")
    print("样本总数 %d，正常样本 %d" % (len(attacks), len(normals)))
    print("\n%-14s %4s %8s %8s %10s %5s %4s" %
          ("家族", "样本", "train覆盖", "test覆盖", "单规则基线", "正常命中", "特指"))
    for fam, n, tr, te, base, fp, spec in rows:
        if tr == "-":
            print("%-14s %4d %8s %8s %10s %5s %4s" % (fam, n, tr, te, base, fp, spec))
        else:
            print("%-14s %4d %7.0f%% %7.0f%% %9.0f%% %5d %4s" %
                  (fam, n, tr, te, base, fp, spec))
    if fam_total:
        print("\n家族规则留出覆盖率: %d/%d = %.0f%%" %
              (fam_ok, fam_total, 100.0 * fam_ok / fam_total))
        print("单样本基线留出覆盖率: %d/%d = %.0f%%" %
              (base_ok, base_total, 100.0 * base_ok / base_total))
    other = {k: v for k, v in groups.items() if k.endswith(":other")}
    if other:
        print("\n未归入已知家族的样本 %d 条:" % sum(len(v) for v in other.values()))
        for k, v in sorted(other.items()):
            print("  - %s: %d" % (k, len(v)))
    return rows


if __name__ == "__main__":
    evaluate()
