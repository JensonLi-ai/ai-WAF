"""闭环引擎：轮询日志 -> 延迟研判 -> 高置信度变种生成观察期规则 -> 生命周期维护。

规则生命周期（用户确认的硬约束）：
- 观察期 OBSERVE_TTL_DAYS 天，独立统计命中
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
    r"__class__|__globals__|__subclasses__|"
    # XML / XXE / Office 公式注入
    r"<!ENTITY|<!DOCTYPE|<%[=#]?|O:\d+:"
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
    return False, "too-broad literals=%r" % sorted(words)[:5]


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
        for row in rows:
            self._analyze_one(row)

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
        a = self.llm.analyze(ev)
        db.save_analysis(row["id"], a)
        short = (row["attack_type"] or "?")[:24]
        log("analyze #%s [%s] -> %s (%.2f) %s" %
            (row["safeline_id"], short, a["verdict"], a["confidence"],
             a["explain"][:60]))
        if (a["verdict"] == "attack"
                and a["confidence"] >= config.MIN_CONFIDENCE
                and not a.get("_error")):
            row2 = dict(row)
            row2["payload"] = ev.get("payload") or row.get("payload") or ""
            self._maybe_create_rule(row2, a)

    def _maybe_create_rule(self, row, a):
        regex = re.sub(r"^/|\s*$", "", (a.get("suggested_rule") or "").strip()
                       ).strip("/")
        if not regex or len(regex) > 512:
            log("skip rule: ill-formed regex (%d chars)" % len(regex))
            return
        try:
            re.compile(regex)
        except re.error as e:
            log("skip rule: invalid regex %r: %s" % (regex, e))
            return
        sample = "%s %s" % (row.get("uri") or "", row.get("payload") or "")
        if sample.strip() and not re.search(regex, sample):
            log("skip rule: regex does not match triggering sample: %r" % regex[:60])
            return
        ok, why = _regex_specific_enough(regex)
        if not ok:
            log("skip rule: regex too broad (%s): %r" % (why, regex[:60]))
            return
        if db.rule_regex_exists(regex):
            log("skip rule: regex already covered: %r" % regex[:60])
            return
        host = row["host"] or None
        site_id = config.DEFAULT_SITE_ID or None
        if config.REQUIRE_SITE_BINDING and not site_id and not host:
            log("skip rule: no site/host to bind (REQUIRE_SITE_BINDING)")
            return
        prefix = _uri_prefix(row.get("uri"))
        name = "AI-%s-%s" % (_slug(a.get("variant")),
                             hashlib.md5(regex.encode()).hexdigest()[:8])
        conditions = self.safeline.build_conditions(
            uri_regex=regex, host=host, site_id=site_id)
        policy_id = self._create_policy_with_site_op_fallback(name, conditions)
        if policy_id is None:
            return
        db.add_rule(
            name=name, regex=regex, site_id=site_id or host, host=host,
            uri_prefix=prefix,
            observed_until=_iso(_now() + timedelta(days=config.OBSERVE_TTL_DAYS)),
            safeline_policy_id=policy_id, confidence=a["confidence"])
        log("rule created: %s (policy_id=%s) prefix=%s conf=%.2f" %
            (name, policy_id, prefix, a["confidence"]))

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
            self._collect_normal(line)
        cands = self._extract_miss_candidates(lines)
        for cand in cands[:config.MISS_MAX_BATCH]:
            self._analyze_miss(cand)

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

    def _regex_hits_normal(self, regex):
        """回放正常流量池：正则命中任意一条正常请求即返回 True（会误杀）。"""
        if not config.PROMOTE_GUARD_ENABLED:
            return False
        if db.normal_pool_count() < config.NORMAL_POOL_MIN:
            return False  # 池子样本太少，回放无意义，放行转正
        try:
            rx = re.compile(regex)
        except re.error:
            return False
        for text in db.normal_pool_texts():
            if rx.search(text[:4096]):
                return True
        return False

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
                if self._regex_hits_normal(r["regex"]):
                    self._delete_rule(
                        r, "promote-guard: matches normal traffic")
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
            combined = "(?:" + "|".join(sorted(set(m["regex"] for m in members))) + ")"
            if len(combined) > 512:
                continue  # 合并后过大则保持独立
            policies = {str(p.get("id")): p
                        for p in self.safeline.list_policies(page_size=100)}
            pol = policies.get(str(leader["safeline_policy_id"]))
            if not pol:
                continue
            try:
                for group in (pol.get("pattern") or []):
                    for cond in (group or []):
                        if cond.get("k") == "uri":
                            cond["v"] = [combined]
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