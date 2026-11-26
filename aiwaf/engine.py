"""闭环引擎：轮询日志 -> 延迟研判 -> 高置信度变种生成观察期规则 -> 生命周期维护。

规则生命周期（用户确认的硬约束）：
- 观察期 OBSERVE_TTL_HOURS 小时，独立统计命中
- 观察期到期且命中 >= PROMOTE_THRESHOLD_HITS 转正；到期未达标直接回收
- 转正后连续 PROMOTE_ZERO_HIT_DAYS 天零命中自动回收
- 转正后同类规则（同 host+uri 前缀）合并为复合正则
- 活跃规则总量上限 MAX_RULES，超限按 命中×置信度+新鲜度 打分淘汰
"""
import hashlib
import json
import re
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import unquote

from . import config, db

MAX_ANALYZE_BATCH = 4      # 每个轮询周期最多研判的事件数
MAX_POLL_PAGES = 5         # 每次轮询最多翻的日志页数

# 漏判候选粗筛：仅在 URI/query 出现这些高信号攻击特征时才送 LLM 研判。
# 过渡方案——LLM 做最终判定，此处只过滤明显正常请求，省 LLM 调用。
MISS_SUSPECT_RE = re.compile(
    r"(?is)"
    # XSS / HTML 注入
    r"<svg|<script|<img[^>]*(onerror|onload)|"
    r"\bon(load|error|click|mouseover|mouseout|focus|blur|change|submit|"
    r"keyup|keydown|scroll|input)\s*=|"
    r"javascript\s*:|document\.cookie|\b(alert|prompt|confirm)\s*\(|"
    # SQL 注入
    r"'\s*or\s+'|union\s+(all\s+)?select|\bor\s+\d+\s*=\s*\d+|"
    r"information_schema|\b(sleep|benchmark|pg_sleep)\s*\(|"
    # 命令注入
    r"\|\s*(id|whoami|cat|ls|sh|bash|net|ping|wget|curl|nc|nslookup)\b|"
    r"&&\s*\w+|;\s*(id|whoami|cat|ls)\b|"
    r"`[^`]+`|\$\([^)]*\)|\b(eval|exec|system)\s*\(|"
    # 路径穿越
    r"\.\./|\.\.\\|%2e%2e|"
    # SSRF
    r"\b(file|gopher|dict|ldap)://|127\.0\.0\.1|169\.254\.169\.254|"
    # 模板注入 (EL / SpEL / Thymeleaf / 通用 SSTI)
    r"\$\{[^}]+\}|\{\{[^{}]*\}\}|\#\{[^}]+\}|@\{[^}]+\}|"
    r"__class__|__globals__|__subclasses__|jndi:|"
    # 针对 AI 研判层的提示词注入
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions|"
    r"忽略.{0,8}(指令|规则)|system\s*prompt|<\|im_start\|>|"
    # XML / XXE / Office 公式注入
    r"<!ENTITY|<!DOCTYPE|<%[=#]?|O:\d+:|"
    # NoSQL 注入
    r"\[\$(?:ne|gt|gte|lt|lte|regex|where|exists|in|nin)\]|"
    # CRLF 头注入（编码或裸回车换行后接敏感头）
    r"%0d%0a(?:set-cookie|location|content-length)|"
    r"\r\n(?:set-cookie|location|content-length)|"
    # LDAP 注入
    r"\*\)\(\w+=\*|\)\s*\(\s*\|\s*\("
)


def log(msg):
    print("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg), flush=True)


def _iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _now():
    return datetime.now()


# ---- 规则特指性校验 ----
# 过于宽泛的规则在"观察→转正拦截"后会大面积误杀正常业务，例如 \bsleep\s*\(
# 会命中任何含 sleep( 的请求。判定：正则里"有辨识度的字面词"过少、且不含
# 明确的攻击语法标记时，视为过泛，拒绝下发。
_ATTACK_MARKERS = (
    "../", "..\\", "%2e%2e", "169.254", "127.0.0.1",
    "${", "#{", "@{", "{{", "<!ENTITY", "<!DOCTYPE",
    "<script", "onerror", "onload", "javascript:", "$(",
)
_LITERAL_RE = re.compile(r"[A-Za-z0-9_]{3,}")
_DEESCAPE_RE = re.compile(r"\\(.)")
# 提取字面词前先剔除字符类转义（\b \s \d \w 等），否则 \bbenchmark
# 会被连成 "bbenchmark"（10 字符）而误判为强特征词
_CHARCLASS_ESC_RE = re.compile(r"\\[bBdDsSwW]")


def _regex_specific_enough(regex):
    """粗判规则是否足够特指，返回 (ok, reason)。

    放行条件（任一即可）：含明确攻击语法标记 / 有 >=2 个不同字面词 /
    单个强特征词(length>=10)。否则视为过泛，拒绝下发。
    """
    # 先把正则里的转义还原成字面字符，便于匹配 ${ ../ <script 等真实标记
    stripped = _DEESCAPE_RE.sub(r"\1", regex).lower()
    for marker in _ATTACK_MARKERS:
        if marker in stripped:
            return True, "attack-marker"
    words = set(w.lower()
                for w in _LITERAL_RE.findall(_CHARCLASS_ESC_RE.sub(" ", regex)))
    if len(words) >= 2:
        return True, "multi-token"
    # 单个强特征词（如 xp_cmdshell / information_schema）可放行；
    # 短通用词（sleep/benchmark/select/admin 等）一律拦下。
    if any(len(w) >= 10 for w in words):
        return True, "long-token"
    # 结构性攻击语法：引号闭合+注释/分号、管道与逻辑符、事件处理器函数、成对反引号。
    # 这类规则即使只有一个普通字面词也足够特指，例如 admin'\s*--、';alert\(1\)
    flat = re.sub(r"\\s[*+?]?", "", regex.lower())
    flat = re.sub(r"\\([^A-Za-z0-9])", r"\1", flat)
    if flat.count("`") >= 2:
        return True, "struct-marker"
    # 多个百分号编码片段（%27、%2f、%3d）本身就是足够强的特征
    if len(re.findall(r"%[0-9a-f]{2}", flat)) >= 2:
        return True, "encoded-marker"
    # PHP/Java 序列化头 O:8:... / aced0005 结构
    if re.search(r"o:(?:\\d\+?|\d+):", flat) or "aced00" in flat:
        return True, "struct-marker"
    words2 = set(w.lower() for w in
                 re.findall(r"[A-Za-z0-9_]{2,}", _CHARCLASS_ESC_RE.sub(" ", regex)))
    # 编码后的攻击标点（%7c=| %3b=; %27=' %3c=< %60=` …）等同字面标点
    for marker in ("'--", "'#", "';", '";', "&&", "||", "--",
                   "%7c", "%3b", "%26", "%3c", "%3e", "%27", "%22",
                   "%60", "%24", "%23", "alert(", "prompt(", "confirm("):
        if marker in flat and (words2 or marker in ("alert(", "prompt(", "confirm(")):
            return True, "struct-marker"
    return False, "too-broad literals=%r" % sorted(words)[:5]


# \b 紧跟在非单词字符之后（如 &&\b、'\b）永远不成立，是模型常见笔误。
_BAD_BOUNDARY_RE = re.compile(r"""(?<=[&|;'"`<>/=,:({\[.\\])\\b""")


def _rule_matches(rule, sample):
    try:
        rx = re.compile(rule)
    except re.error:
        return False
    return (not sample) or bool(rx.search(sample))


# ReDoS 启发式：嵌套量词 (a+)+ / (.*)* 是灾难性回溯的典型结构
_NESTED_QUANT_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")


def _regex_risky(regex):
    return bool(_NESTED_QUANT_RE.search(regex or ""))


def _rule_usable(rule, sample):
    return bool(rule) and not _regex_risky(rule) \
        and _rule_matches(rule, sample) \
        and _regex_specific_enough(rule)[0]


def _contextualize(rule, sample):
    r"""规则过泛时，用样本中紧邻的上下文词把它收紧（仍能命中该样本）。

    例：\bsleep\s*\( 在 "1 AND sleep(5)" 上收成 AND\W*(?:\bsleep\s*\()
    """
    # (?i) 等全局标志必须留在整条规则开头，包进分组里会编译失败
    flags = ""
    fm = re.match(r"\(\?[aiLmsux]+\)", rule)
    if fm:
        flags, rule = fm.group(0), rule[fm.end():]
    try:
        m = re.search(rule, sample)
    except re.error:
        return None
    if not m:
        return None
    left, right = sample[:m.start()], sample[m.end():]
    lt = re.search(r"([A-Za-z0-9_]{2,16})\W*$", left)
    rt = re.match(r"\W*([A-Za-z0-9_]{2,16})", right)
    if not lt and not rt:
        return None
    parts = []
    if lt:
        parts.append(re.escape(lt.group(1)) + r"\W*")
    parts.append("(?:" + rule + ")")
    if rt:
        parts.append(r"\W*" + re.escape(rt.group(1)))
    return flags + "".join(parts)


def _repair_candidates(rule, sample):
    """枚举模型规则的确定性修复候选（不改变攻击语义）。"""
    base = (rule or "").strip()
    # 去掉 JS 风格的包裹斜杠 /.../，但不要误删规则自带的路径首斜杠
    if len(base) > 2 and base.startswith("/") and base.endswith("/"):
        base = base[1:-1]
    if not base:
        return []
    cands = [base]
    fixed = _fix_broken_regex(base)
    if fixed and fixed != base:
        cands.append(fixed)
    # 双重转义：模型把 \d 误写成 \\d（JSON 里过度转义）
    for c in list(cands):
        d = c.replace("\\\\", "\\")
        if d != c:
            cands.append(d)
    for c in list(cands):
        d = _BAD_BOUNDARY_RE.sub("", c)
        if d != c:
            cands.append(d)
    sample = sample or ""
    # 样本空格被编码成 %20 时，\s* 要同时接受 %20
    if "%20" in sample.lower():
        for c in list(cands):
            d = c.replace(r"\s*", r"(?:\s|%20|\+)*") \
                 .replace(r"\s+", r"(?:\s|%20|\+)+")
            if d != c:
                cands.append(d)
    # 样本是 URL 编码原文时，\xHH 应改成 %HH 才能匹配
    if "%" in sample:
        for c in list(cands):
            d = re.sub(r"\\x([0-9a-fA-F]{2})",
                       lambda m: "%" + m.group(1).upper(), c)
            if d != c:
                cands.append(d)
    # 引号风格不一致（payload 单引号、规则双引号）
    for c in list(cands):
        if '"' in c and "'" in sample:
            cands.append(c.replace('"', "'"))
        if "'" in c and '"' in sample:
            cands.append(c.replace("'", '"'))
    # 大小写不敏感兜底（URL 编码大小写、命令大小写绕过）
    for c in list(cands):
        cands.append("(?i)" + c)
    return cands


def _repair_rule(rule, sample):
    """对模型正则做修复，返回首个可落地（可编译+命中+特指）版本，失败返回 None。"""
    for c in _repair_candidates(rule, sample):
        if _rule_usable(c, sample):
            return c
        if _rule_matches(c, sample):
            ctx = _contextualize(c, sample)
            if ctx and _rule_usable(ctx, sample):
                return ctx
    return None


_INLINE_FLAGS_RE = re.compile(r"^\(\?([aiLmsux]+)\)")


def _scope_inline_flags(regex):
    """把开头的全局内联标志 (?i) 转成作用域形式 (?i:...)，避免拼接后编译失败。"""
    m = _INLINE_FLAGS_RE.match(regex or "")
    if not m:
        return regex
    return "(?%s:%s)" % (m.group(1), regex[m.end():])


def _scoped_uri_regex(prefix, regex):
    """把 URI 前缀拼进雷池的 uri 条件，确保规则只在该路径下生效。

    前缀后必须是 '/'、'?' 或结尾，避免 /train 误匹配 /training；
    根路径 '/' 视为全站，不额外加限制。
    """
    scoped = _scope_inline_flags(regex or "")
    prefix = (prefix or "/").rstrip("/")
    if not prefix:
        return scoped
    return r"^%s(?:[/?]|$).*(?:%s)" % (re.escape(prefix), scoped)


def _llm_anchor_rule(payload, anchors):
    """用模型逐字给出的攻击锚点拼规则，锚点必须原样出现在 payload 中。

    模型不擅长写正则、但擅长"指出哪段是攻击特征"。这里只采信 payload 里
    逐字出现的锚点，按出现顺序用非贪婪间隔拼接，既保证命中原文，又允许
    攻击者插入少量变形字符。
    """
    if not payload or not anchors:
        return None
    vals = []
    for a in anchors:
        a = (a or "").strip()
        if a and len(a) <= 120 and a in payload:
            vals.append(a)
    if not vals:
        return None
    # 去重：短锚点若已被更长锚点包含则丢弃
    uniq = []
    for a in sorted(set(vals), key=len, reverse=True):
        if not any(a in b for b in uniq):
            uniq.append(a)
    uniq.sort(key=payload.find)
    parts = [re.escape(a) for a in uniq]
    rule = r".{0,40}?".join(parts)
    if len(rule) > 400:
        return None
    if _rule_usable(rule, payload):
        return rule
    # 两段以上的逐字锚点本身已足够特指（模型的中文词表阈值会低估纯符号锚点）
    if len(uniq) >= 2 and sum(len(a) for a in uniq) >= 6:
        return rule
    # 锚点过短（如 |id）导致特指性不足时，用 payload 上下文收紧
    ctx = _contextualize(rule, payload)
    if ctx and _rule_usable(ctx, payload):
        return ctx
    return None


def _fix_broken_regex(regex):
    """模型输出的正则常见缺陷：以裸反斜杠结尾（JSON 转义没写对）。

    安全修复：剥掉结尾连续反斜杠后重编译；仍不合法则返回 None。
    """
    fixed = re.sub(r"\\+$", "", regex)
    if not fixed:
        return None
    try:
        re.compile(fixed)
        return fixed
    except re.error:
        return None


def _literal_rule(row):
    """从触发样本提炼字面正则兜底（模型正则失败时的安全网）。

    对 payload 做正则转义得到精确字面匹配，保证至少能拦住同一 payload
    的后续重放。payload 为空或无法保证特指性时返回 None。
    """
    payload = (row.get("payload") or "").strip()
    if not payload:
        return None
    esc = re.escape(payload)
    if len(esc) > 200:
        esc = esc[:200]
        # 截断可能切在转义序列中间（末尾裸反斜杠），逐步回退到可编译
        while esc:
            cand = re.sub(r"\\+$", "", esc)
            try:
                re.compile(cand)
                esc = cand
                break
            except re.error:
                esc = esc[:-1]
        if not esc:
            return None
    if not _regex_specific_enough(esc)[0]:
        return None
    return esc


_CMDI_CMDS = (
    "id", "whoami", "cat", "ls", "pwd", "sh", "bash", "uname",
    "ifconfig", "ipconfig", "net", "ping", "wget", "curl", "nc",
    "nslookup", "dir", "type", "systeminfo", "hostname",
    "powershell", "python", "python3", "perl", "rm", "chmod", "chown",
    "kill", "tasklist", "certutil", "bitsadmin", "regsvr32", "mshta",
)


def _anchor_rule(payload):
    """锚点提取：针对短 payload（字面规则特指性不足）提炼适度泛化的攻击规则。

    仅识别白名单内的攻击语法锚点（管道/分号/反引号/$()/引号闭合/注释/恒真式/
    alert 等），确定性构造规则，不依赖 LLM 生成。锚点本身即特指性保证，
    误杀风险靠转正前正常池回放兜底。
    """
    p = payload or ""
    if not p:
        return None
    # XSS：alert/prompt/confirm（优先，避免 ;alert 被误判为命令注入）
    m = re.search(r'\b(alert|prompt|confirm)\s*\(', p, re.I)
    if m:
        return r'\b' + m.group(1).lower() + r'\s*\('
    # 命令注入：反引号
    if p.count('`') >= 2:
        return r"`[^`]+`"
    # 命令注入：$()
    if '$(' in p:
        return r'\$\([^)]*\)'
    # 命令注入：管道符 |cmd（白名单命令名）
    m = re.search(r'\|\s*([A-Za-z0-9_./-]{1,32})', p)
    if m and m.group(1).lower() in _CMDI_CMDS:
        return r'\|\s*' + re.escape(m.group(1))
    # 命令注入：分号 ;cmd（白名单命令名）
    m = re.search(r';\s*([A-Za-z0-9_./-]{1,32})', p)
    if m and m.group(1).lower() in _CMDI_CMDS:
        return r';\s*' + re.escape(m.group(1))
    # 命令/SQL 注入：分号或管道 + 延时函数（如 1;sleep(10)）
    m = re.search(r'[;|]\s*(sleep|benchmark|pg_sleep)\s*\(', p, re.I)
    if m:
        return r'(?i)[;|]\s*' + m.group(1).lower() + r'\s*\('
    # 命令注入：分号 + sleep/ping + 秒数（如 1;sleep 10）
    m = re.search(r'[;|]\s*(sleep|ping)\s+\d{1,3}\b', p, re.I)
    if m:
        return r'(?i)[;|]\s*' + m.group(1).lower() + r'\s+\d{1,3}\b'
    # SQL：and/or + 延时函数（时间盲注）
    m = re.search(r'\b(and|or)\s+(sleep|benchmark|pg_sleep)\s*\(', p, re.I)
    if m:
        return r'(?i)\b(and|or)\s+' + m.group(2).lower() + r'\s*\('
    # SQL Server：WAITFOR DELAY / xp_cmdshell（优先于引号+注释的宽规则）
    if re.search(r'\bwaitfor\s+delay\b', p, re.I):
        return r'(?i)\bwaitfor\s+delay\b'
    if re.search(r'\bxp_cmdshell\b', p, re.I):
        return r'(?i)\bxp_cmdshell\b'
    # SQL：引号闭合 + or/and
    m = re.search(r"'\s*(or|and)\b", p, re.I)
    if m:
        return r"(?i)'\s*(or|and)\b"
    # SQL：引号 + 注释
    if re.search(r"'\s*--", p) or re.search(r"'\s*#", p):
        return r"'\s*(--|#)"
    # SQL：恒真式 + 注释
    if re.search(r'\b(or|and)\b', p, re.I) and '--' in p:
        return r'(?i)\b(or|and)\b.*--'
    return None


def _resolve_rule_ex(row, a, sample):
    """返回 (regex, source)，source ∈ model / anchor / literal / syntax。

    规则内容优先由 LLM 产出：模型正则 -> LLM 逐字锚点 -> payload 字面兜底；
    最后才是确定性语法锚点（可用 ALLOW_SYNTAX_FALLBACK=0 关闭）。
    """
    candidate = (a.get("suggested_rule") or "").strip()
    if len(candidate) <= 512:
        repaired = _repair_rule(candidate, sample)
        if repaired:
            return repaired, "model"
    anchored = _llm_anchor_rule(row.get("payload") or sample,
                                a.get("rule_anchors") or [])
    if anchored:
        return anchored, "anchor"
    literal = _literal_rule(row)
    if literal:
        return literal, "literal"
    if not config.ALLOW_SYNTAX_FALLBACK:
        return None, None
    syntax = _anchor_rule(row.get("payload") or "")
    if syntax:
        return syntax, "syntax"
    return None, None


def _resolve_rule(row, a, sample):
    """兼容旧调用：只返回正则（来源统计用 _resolve_rule_ex）。"""
    return _resolve_rule_ex(row, a, sample)[0]


def _parse_ts(s, default=None):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s[:19], fmt)
        except (ValueError, TypeError):
            continue
    return default


def _uri_prefix(uri):
    """提取 URI 路径前缀（'/' + 第一段），规则匹配范围收敛到该前缀。"""
    if not uri:
        return "/"
    path = uri.split("?", 1)[0].strip() or "/"
    seg = path.split("/", 2)[1] if path.startswith("/") else path.split("/", 1)[0]
    if seg:
        return "/" + seg
    return "/"


def _slug(s, n=16):
    s = re.sub(r"[^A-Za-z0-9_-]+", "_", (s or "").strip(" _"))
    return (s or "variant")[:n]


class Engine(threading.Thread):
    def __init__(self, safeline, llm):
        super().__init__(daemon=True, name="aiwaf-engine")
        self.safeline = safeline
        self.llm = llm
        self._miss_seen = set()
        self._miss_backlog = deque()
        self._m_lock = threading.Lock()
        self._latencies = deque(maxlen=500)
        self._started_at = time.time()
        self.metrics = {
            "analysis_total": 0, "cache_hits": 0, "llm_calls": 0,
            "llm_errors": 0, "timeouts": 0, "rules_created": 0,
        }

    def _metric(self, name, delta=1):
        with self._m_lock:
            self.metrics[name] = self.metrics.get(name, 0) + delta

    def _record_latency(self, ms):
        with self._m_lock:
            self._latencies.append(ms)

    def metrics_snapshot(self):
        with self._m_lock:
            lat = sorted(self._latencies)
            m = dict(self.metrics)

        def pct(p):
            if not lat:
                return 0
            idx = min(len(lat) - 1, int(len(lat) * p))
            return round(lat[idx])

        m.update({
            "uptime_sec": round(time.time() - self._started_at),
            "latency_samples": len(lat),
            "latency_p50_ms": pct(0.50),
            "latency_p95_ms": pct(0.95),
            "latency_p99_ms": pct(0.99),
            "run_mode": config.RUN_MODE,
            "llm_concurrency": config.LLM_CONCURRENCY,
        })
        return m

    # ---------------- 主循环 ----------------

    def run(self):
        log("engine start: poll=%ss analyze_delay=%ss" %
            (config.POLL_INTERVAL, config.ANALYZE_DELAY))
        while True:
            try:
                self.poll_events()
            except Exception as e:
                log("poll_events error: %s" % e)
            try:
                self.analyze_pending()
            except Exception as e:
                log("analyze_pending error: %s" % e)
            if config.MISS_POLL_ENABLED:
                try:
                    self.poll_misses()
                except Exception as e:
                    log("poll_misses error: %s" % e)
            try:
                self.maintenance()
            except Exception as e:
                log("maintenance error: %s" % e)
            time.sleep(config.POLL_INTERVAL)

    # ---------------- 1. 日志轮询 ----------------

    def poll_events(self):
        # 数据源 /api/open/records（攻击日志记录，EventId/复合键去重）
        total_new = 0
        for page in range(1, MAX_POLL_PAGES + 1):
            res = self.safeline.list_records(
                page=page, page_size=config.SAFELINE_PAGE_SIZE)
            recs = res.get("records") or []
            if not recs:
                break
            new_ids, _ = db.insert_events(recs)
            total_new += len(new_ids)
            if len(recs) < config.SAFELINE_PAGE_SIZE:
                break
        if total_new:
            log("poll: +%d new records" % total_new)

    # ---------------- 2. 研判 ----------------

    def analyze_pending(self):
        rows = db.pending_analyses(MAX_ANALYZE_BATCH, config.ANALYZE_DELAY)
        if not rows:
            return
        workers = max(1, min(config.LLM_CONCURRENCY, len(rows)))
        if workers <= 1:
            for row in rows:
                self._safe_analyze(row)
            return
        # 并发研判：llama-server 支持多槽位，串行是吞吐瓶颈
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="aiwaf-llm") as ex:
            list(ex.map(self._safe_analyze, rows))

    def _safe_analyze(self, row):
        try:
            self._analyze_one(row)
        except Exception as e:
            log("analyze #%s error: %s" % (row.get("safeline_id"), e))

    def _analyze_one(self, row):
        # 拉取完整 payload（失败则退回台账列表字段）
        rid = row["resource_id"] or row["safeline_id"]
        detail = {}
        try:
            detail = self.safeline.get_record(rid) or {}
        except Exception as e:
            log("get_record %s failed: %s" % (rid, e))
        ev = {k: (v or "") for k, v in detail.items()}
        ev.setdefault("safeline_id", row["safeline_id"])
        ev.setdefault("host", row["host"])
        ev.setdefault("uri", row["uri"])
        ev.setdefault("attack_type", row["attack_type"])
        key = db.cache_key(ev.get("host") or row["host"],
                           ev.get("uri") or row["uri"],
                           ev.get("payload") or row.get("payload") or "")
        t0 = time.perf_counter()
        a = db.get_cached_analysis(key) if config.ANALYSIS_CACHE_ENABLED else None
        if a:
            self._metric("cache_hits")
            log("cache hit #%s (saved LLM call)" % row["safeline_id"])
        else:
            self._metric("llm_calls")
            a = self.llm.analyze(ev)
            if a.get("_error"):
                self._metric("llm_errors")
                if "timeout" in (a.get("explain") or "").lower():
                    self._metric("timeouts")
            elif config.ANALYSIS_CACHE_ENABLED:
                db.put_cached_analysis(
                    key, ev.get("host") or row["host"],
                    ev.get("uri") or row["uri"],
                    ev.get("payload") or row.get("payload") or "", a)
        self._metric("analysis_total")
        self._record_latency((time.perf_counter() - t0) * 1000)
        db.save_analysis(row["id"], a)
        short = (row["attack_type"] or "?")[:24]
        log("analyze #%s [%s] -> %s (%.2f) %s" %
            (row["safeline_id"], short, a["verdict"], a["confidence"],
             a["explain"][:60]))
        if (a["verdict"] == "attack"
                and a["confidence"] >= config.MIN_CONFIDENCE
                and not a.get("_error")):
            if config.RUN_MODE == "alert-only":
                log("alert (no rule): [%s] %s conf=%.2f" %
                    (short, a["explain"][:40], a["confidence"]))
                return
            row2 = dict(row)
            row2["payload"] = ev.get("payload") or row.get("payload") or ""
            self._maybe_create_rule(row2, a)

    def _maybe_create_rule(self, row, a):
        sample = ("%s %s" % (row.get("uri") or "",
                             row.get("payload") or "")).strip()
        regex, regex_source = _resolve_rule_ex(row, a, sample)
        if regex is None:
            log("skip rule: no valid regex (LLM rule/anchor + fallback failed, "
                "syntax_fallback=%s)" %
                ("on" if config.ALLOW_SYNTAX_FALLBACK else "off"))
            return
        host = row["host"] or None
        site_id = config.DEFAULT_SITE_ID or None
        if config.REQUIRE_SITE_BINDING and not site_id and not host:
            log("skip rule: no site/host to bind (REQUIRE_SITE_BINDING)")
            return
        prefix = _uri_prefix(row.get("uri"))
        scope = "%s|%s" % (host or "", prefix)
        if db.rule_regex_exists(regex, host=host or "", prefix=prefix):
            log("skip rule: regex already covered in scope %s: %r" %
                (scope, regex[:60]))
            return
        name = "AI-%s-%s" % (
            _slug(a.get("variant")),
            hashlib.md5((regex + "|" + scope).encode()).hexdigest()[:8])
        conditions = self.safeline.build_conditions(
            uri_regex=_scoped_uri_regex(prefix, regex),
            host=host, site_id=site_id)
        policy_id = self._create_policy_with_site_op_fallback(name, conditions)
        if policy_id is None:
            return
        db.add_rule(
            name=name, regex=regex, site_id=site_id or host, host=host,
            uri_prefix=prefix,
            observed_until=_iso(_now() + timedelta(hours=config.OBSERVE_TTL_HOURS)),
            safeline_policy_id=policy_id, confidence=a["confidence"],
            source="ai-closed-loop", regex_source=regex_source,
            sample=sample)
        self._metric("rules_created")
        log("rule created: %s (policy_id=%s) prefix=%s source=%s conf=%.2f" %
            (name, policy_id, prefix, regex_source, a["confidence"]))

    def _create_policy_with_site_op_fallback(self, name, conditions):
        """站点条件 op 不确定时先 in 后 eq，兼容两种后端写法。

        conditions 为二维数组（外层 OR 组），需遍历内层条件。
        """
        try:
            return self.safeline.create_policy(name, conditions)
        except Exception as e:
            if getattr(e, "status", None) != 400:
                log("create_policy failed: %s" % e)
                return None
            has_site = any(c.get("k") == "website"
                           for group in conditions for c in group)
            if not has_site:
                log("create_policy failed: %s" % e)
                return None
            fixed = [[dict(c) for c in group] for group in conditions]
            for group in fixed:
                for c in group:
                    if c.get("k") == "website":
                        c["op"] = "eq"
            try:
                return self.safeline.create_policy(name, fixed)
            except Exception as e2:
                log("create_policy retry failed: %s" % e2)
                return None

    # ---------------- 2.5 漏判检测（放行流量来源） ----------------

    def poll_misses(self):
        lines = self._read_miss_log()
        if not lines:
            return
        for line in lines:
            try:
                self._collect_normal(line)
            except Exception as e:
                log("collect normal failed: %s" % e)
        cands = self._extract_miss_candidates(lines)
        # 超出单轮上限的候选进 backlog，下一轮继续处理，避免静默丢弃
        self._miss_backlog.extend(cands)
        backlog_cap = max(100, config.MISS_MAX_BATCH * 50)
        while len(self._miss_backlog) > backlog_cap:
            self._miss_backlog.popleft()
        if cands and len(self._miss_backlog) > config.MISS_MAX_BATCH:
            log("miss backlog: +%d, %d pending" %
                (len(cands), len(self._miss_backlog)))
        processed = 0
        while self._miss_backlog and processed < config.MISS_MAX_BATCH:
            cand = self._miss_backlog.popleft()
            try:
                self._analyze_miss(cand)
            except Exception as e:
                # 单条失败只跳过该条，不能让整批漏判候选一起丢
                log("miss analyze failed (%s): %s" %
                    (cand.get("uri", "")[:80], e))
            processed += 1
        if len(self._miss_seen) > 50000:
            self._miss_seen.clear()

    def _read_miss_log(self):
        """增量读取本地放行流量 JSONL（旁路记录后端写入）。"""
        path = config.MISS_LOG_PATH
        offset = int(db.get_kv("miss_log_offset", "0") or 0)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                if offset > 0:
                    f.seek(offset)
                data = f.read()
                new_offset = f.tell()
        except FileNotFoundError:
            return []
        if not data:
            return []
        db.set_kv("miss_log_offset", str(new_offset))
        return [l for l in data.splitlines() if l.strip()]

    def _collect_normal(self, line):
        """粗筛未命中的放行流量视为正常，写入正常流量池（供转正前回放）。"""
        if not config.PROMOTE_GUARD_ENABLED:
            return
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            return
        raw_uri = obj.get("raw_uri") or obj.get("uri") or ""
        if not raw_uri:
            return
        try:
            uri = unquote(raw_uri)
        except Exception:
            uri = raw_uri
        if MISS_SUSPECT_RE.search(uri):
            return  # 疑似攻击，不进正常池
        db.add_normal(uri, host=obj.get("host", ""), uri=uri,
                      src_ip=obj.get("src_ip", ""))

    def _extract_miss_candidates(self, lines):
        out = []
        for line in lines:
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                continue
            raw_uri = obj.get("raw_uri") or obj.get("uri") or ""
            if not raw_uri:
                continue
            try:
                uri = unquote(raw_uri)
            except Exception:
                uri = raw_uri
            if not MISS_SUSPECT_RE.search(uri):
                continue
            host = obj.get("host", "")
            client = obj.get("src_ip", "")
            key = hashlib.md5(
                (client + " " + host + " " + uri).encode()).hexdigest()
            if key in self._miss_seen:
                continue
            self._miss_seen.add(key)
            out.append({"client": client, "host": host, "uri": uri,
                        "method": obj.get("method", "")})
        return out

    def _analyze_miss(self, cand):
        query = ""
        if "?" in cand["uri"]:
            query = cand["uri"].split("?", 1)[1]
        ev = {
            "host": cand["host"],
            "uri": cand["uri"],
            "payload": query or cand["uri"],
            "src_ip": cand["client"],
        }
        a = self.llm.analyze(ev)
        log("miss analyze [%s] %s -> %s (%.2f) %s" %
            (cand["client"], cand["host"], a["verdict"], a["confidence"],
             a["explain"][:60]))
        if a["verdict"] == "benign":
            db.add_normal(cand["uri"], host=cand["host"], uri=cand["uri"],
                          src_ip=cand["client"])
        if (a["verdict"] == "attack"
                and a["confidence"] >= config.MIN_CONFIDENCE
                and not a.get("_error")):
            if config.RUN_MODE == "alert-only":
                log("miss alert (no rule): [%s] conf=%.2f" %
                    (cand["client"], a["confidence"]))
                return
            self._maybe_create_rule(
                {"host": cand["host"], "uri": cand["uri"],
                 "payload": query or cand["uri"]}, a)

    # ---------------- 3. 生命周期维护 ----------------

    def maintenance(self):
        last = db.get_kv("last_maint")
        if last:
            t = _parse_ts(last)
            if t and (_now() - t).total_seconds() < config.MAINT_INTERVAL:
                return
        db.set_kv("last_maint", _iso(_now()))
        log("maintenance cycle begin")
        self._count_hits()
        self._sync_policy_hits()
        self._promote_and_merge()
        self._recycle()
        self._evict_if_over_cap()
        log("maintenance cycle done: %d active rules" %
            len(db.active_rules()))

    def _count_hits(self):
        cursor = int(db.get_kv("hit_cursor", "0") or 0)
        rows = db.events_payloads_since(cursor)
        if not rows:
            return
        db.set_kv("hit_cursor", str(rows[-1]["id"]))
        now = _iso(_now())
        for rule in db.active_rules():
            try:
                rx = re.compile(rule["regex"])
            except re.error:
                continue
            hit = 0
            for r in rows:
                text = "%s %s" % ((r["uri"] or ""), (r["payload"] or ""))
                if rx.search(text[:4096]):
                    hit += 1
            if hit:
                db.update_rule(rule["id"], hits=rule["hits"] + hit,
                               last_hit=now, zero_hit_since=None)
                log("rule %s +%d hits" % (rule["name"], hit))

    def _sync_policy_hits(self):
        """从雷池策略计数同步命中数。

        AI 规则创建时 log=False，被拦请求不会进攻击日志，事件侧 _count_hits
        永远数不到；这里以策略的 req_count（累计匹配次数）为准做单调同步，
        否则观察期规则会因 hits=0 被当零命中回收，生命周期无法转正。
        """
        try:
            policies = {}
            for page in range(1, 5):
                batch = self.safeline.list_policies(page=page, page_size=100)
                for p in batch:
                    policies[str(p.get("id"))] = int(p.get("req_count") or 0)
                if len(batch) < 100:
                    break
        except Exception as e:
            log("sync policy hits failed: %s" % e)
            return
        now = _iso(_now())
        for rule in db.active_rules():
            rc = policies.get(str(rule["safeline_policy_id"]))
            if rc and rc > (rule["hits"] or 0):
                db.update_rule(rule["id"], hits=rc, last_hit=now,
                               zero_hit_since=None)
                log("rule %s hits synced: %d" % (rule["name"], rc))

    def _replay_normal(self, regex):
        """回放正常流量池，返回 (status, hits)。

        status:
        - clean        未命中任何正常请求
        - match        命中且复核确认为正常（不能转正）
        - insufficient 正常池样本不足（fail-closed：不转正）
        - invalid      正则无法编译（不转正）
        - disabled     回放开关关闭（由调用方决定）
        命中项先做 LLM 复核：若判定为攻击，说明正常池被绕过粗筛的攻击污染，
        立即隔离该条，不让攻击者用污染样本压制规则。
        """
        if not config.PROMOTE_GUARD_ENABLED:
            return "disabled", []
        if db.normal_pool_count() < config.NORMAL_POOL_MIN:
            return "insufficient", []
        try:
            rx = re.compile(regex)
        except re.error:
            return "invalid", []
        hits = []
        for text in db.normal_pool_texts():
            if rx.search(text[:4096]):
                hits.append(text)
                if len(hits) >= config.PROMOTE_REVIEW_MAX:
                    break
        if not hits:
            return "clean", []
        for text in hits:
            a = self.llm.analyze({"host": "", "uri": text, "payload": text})
            if a["verdict"] == "attack" and not a.get("_error"):
                db.remove_normal(text)
                log("normal-pool quarantine: removed attack-looking entry")
                continue
            # LLM 错误时保守处理：视为正常命中，拒绝转正（fail-closed）
            return "match", hits
        return "clean", []

    def _promote_and_merge(self):
        rules = db.active_rules()
        now = _now()
        for r in rules:
            if r["status"] != "observing":
                continue
            exp = _parse_ts(r["observed_until"])
            if not exp or exp > now:
                continue
            if r["hits"] >= config.PROMOTE_THRESHOLD_HITS:
                status, _hits = self._replay_normal(
                    _scoped_uri_regex(r["uri_prefix"], r["regex"]))
                if status == "match":
                    self._delete_rule(
                        r, "promote-guard: matches normal traffic")
                    continue
                if status in ("insufficient", "invalid"):
                    # fail-closed：正常池不够或正则不可编译时保持观察期，不转正
                    log("rule promotion deferred (%s): %s" %
                        (status, r["name"]))
                    continue
                if config.RUN_MODE == "human-review":
                    db.update_rule(r["id"], status="pending_review")
                    log("rule pending review: %s (hits=%d)" %
                        (r["name"], r["hits"]))
                    continue
                db.update_rule(r["id"], status="promoted",
                               zero_hit_since=_iso(now))
                log("rule promoted: %s (hits=%d)" % (r["name"], r["hits"]))
            else:
                self._delete_rule(r, "observe expired with %d hits" % r["hits"])
        self._merge_promoted()

    def _merge_promoted(self):
        groups = {}
        for r in db.active_rules():
            if r["status"] == "promoted":
                groups.setdefault((r["host"] or "", r["uri_prefix"] or ""),
                                  []).append(r)
        for (host, prefix), members in groups.items():
            if len(members) < 2:
                continue
            members.sort(key=lambda r: -r["hits"])
            leader = members[0]
            others = members[1:]
            scoped = set(_scope_inline_flags(m["regex"]) for m in members)
            combined = "(?:" + "|".join(sorted(scoped)) + ")"
            combined_uri = _scoped_uri_regex(prefix, combined)
            if len(combined_uri) > 512:
                continue  # 合并后过大则保持独立
            # 合并后的新正则必须重新回放，防止组合产生新的误杀面
            status, _ = self._replay_normal(combined_uri)
            if status in ("match", "insufficient", "invalid"):
                log("merge skipped (%s): %s/%s" % (status, host, prefix))
                continue
            policies = {str(p.get("id")): p
                        for p in self.safeline.list_policies(page_size=100)}
            pol = policies.get(str(leader["safeline_policy_id"]))
            if not pol:
                continue
            try:
                for group in (pol.get("pattern") or []):
                    for cond in (group or []):
                        if cond.get("k") == "uri":
                            cond["v"] = [combined_uri]
                            break
                pol["name"] = "AI-merged-%s" % hashlib.md5(
                    (host + prefix).encode()).hexdigest()[:8]
                self.safeline.update_policy(pol)
            except Exception as e:
                log("merge update failed: %s" % e)
                continue
            for m in others:
                try:
                    self.safeline.switch_policy(m["safeline_policy_id"], False)
                except Exception as e:
                    log("merge disable %s failed: %s" % (m["name"], e))
                db.update_rule(m["id"], merged_into=leader["id"])
            db.update_rule(leader["id"], regex=combined,
                           hits=sum(m["hits"] for m in members))
            log("merged %d rules -> %s (%s)" %
                (len(members), leader["name"], combined[:80]))

    def _recycle(self):
        now = _now()
        for r in db.active_rules():
            if r["status"] != "promoted":
                continue
            zero_since = _parse_ts(r["zero_hit_since"] or r["updated_at"])
            if not zero_since:
                continue
            if (now - zero_since).days >= config.PROMOTE_ZERO_HIT_DAYS:
                self._delete_rule(r, "zero-hit recycle (%dd)" %
                                  (now - zero_since).days)

    def _evict_if_over_cap(self):
        active = db.active_rules()
        if len(active) <= config.MAX_RULES:
            return
        now = _now()
        scored = []
        for r in active:
            last_act = _parse_ts(r["last_hit"] or r["created_at"]) or now
            days = max(0.0, (now - last_act).total_seconds() / 86400.0)
            score = r["hits"] * 10 * r["confidence"] + max(0.0, 7 - days)
            scored.append((score, r))
        scored.sort(key=lambda x: x[0])
        for _, r in scored[:len(active) - config.MAX_RULES]:
            self._delete_rule(r, "evicted over cap")

    def _delete_rule(self, rule, reason):
        try:
            self.safeline.delete_policy(rule["safeline_policy_id"])
        except Exception as e:
            log("delete_policy %s failed: %s" % (rule["name"], e))
            return
        db.update_rule(rule["id"], status="recycled")
        log("rule recycled: %s (%s)" % (rule["name"], reason))

    # ---------------- 人工审批 / 应急回滚 ----------------

    def approve_rule(self, rule_id):
        """人工批准一条待审规则转正（human-review 模式）。"""
        for r in db.all_rules():
            if r["id"] == rule_id:
                if r["status"] != "pending_review":
                    log("approve %s: status=%s not pending" %
                        (r["name"], r["status"]))
                    return False
                db.update_rule(rule_id, status="promoted",
                               zero_hit_since=_iso(_now()))
                log("rule approved & promoted: %s" % r["name"])
                return True
        log("approve: rule %s not found" % rule_id)
        return False

    def rollback_ai_rules(self):
        """批量禁用所有 AI 闭环规则（误杀应急回滚）。"""
        rules = db.list_ai_rules()
        n = 0
        for r in rules:
            try:
                self.safeline.switch_policy(r["safeline_policy_id"], False)
                db.update_rule(r["id"], status="recycled")
                n += 1
            except Exception as e:
                log("rollback %s failed: %s" % (r["name"], e))
        log("rollback: disabled %d AI rules" % n)
        return n