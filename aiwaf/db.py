"""AI-WAF 本地台账（sqlite3，纯 stdlib）

三张核心表：
- events    雷池攻击事件台账（safeline_id 唯一去重）
- analyses  每条事件的 LLM 研判结论
- rules     AI 生成规则的台账与生命周期（observing / promoted / recycled）
另有一张 kv 表存引擎游标、维护周期等杂项状态。
"""
import hashlib
import json
import sqlite3
import threading
from datetime import datetime

from . import config

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    safeline_id TEXT UNIQUE NOT NULL,
    resource_id TEXT,
    ts TEXT,
    src_ip TEXT,
    host TEXT,
    port TEXT,
    uri TEXT,
    attack_type TEXT,
    policy_name TEXT,
    payload TEXT,
    raw TEXT,
    analyzed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_analyzed ON events(analyzed, id);

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES events(id),
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    variant TEXT,
    suggested_rule TEXT,
    explain TEXT,
    model TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_event ON analyses(event_id);

CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    regex TEXT NOT NULL,
    site_id TEXT,
    host TEXT,
    uri_prefix TEXT,
    status TEXT NOT NULL DEFAULT 'observing',
    hits INTEGER NOT NULL DEFAULT 0,
    last_hit TEXT,
    zero_hit_since TEXT,
    observed_until TEXT,
    safeline_policy_id INTEGER,
    merged_into INTEGER,
    confidence REAL NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'ai-closed-loop',
    sample TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_active ON rules(status, merged_into);

CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT
);

CREATE TABLE IF NOT EXISTS normal_pool (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup TEXT UNIQUE NOT NULL,
    text TEXT NOT NULL,
    host TEXT,
    uri TEXT,
    src_ip TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_normal_pool_created ON normal_pool(created_at);
"""


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_conn():
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    with _lock:
        conn = get_conn()
        try:
            conn.executescript(SCHEMA)
            _migrate(conn)
            conn.commit()
        finally:
            conn.close()


def _migrate(conn):
    """为已存在的旧库补列（CREATE TABLE IF NOT EXISTS 不会给旧表加新列）。"""
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(rules)")]
    if "source" not in cols:
        conn.execute(
            "ALTER TABLE rules ADD COLUMN source TEXT NOT NULL DEFAULT 'ai-closed-loop'")
    if "sample" not in cols:
        conn.execute("ALTER TABLE rules ADD COLUMN sample TEXT NOT NULL DEFAULT ''")


# ---------------- kv ----------------

def get_kv(key, default=None):
    conn = get_conn()
    try:
        row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
        return row["v"] if row else default
    finally:
        conn.close()


def set_kv(key, value):
    with _lock:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO kv(k,v) VALUES(?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (key, str(value)),
            )
            conn.commit()
        finally:
            conn.close()


# ---------------- events ----------------

def insert_events(nodes):
    """批量写入雷池事件（按 safeline_id 去重）。

    返回 (新入库的本地 id 列表, 本批最大事件时间戳)。
    """
    with _lock:
        conn = get_conn()
        new_ids = []
        max_ts = None
        try:
            for n in nodes:
                # 数据源：/api/open/records（攻击日志记录）。
                # 唯一键：event_id(uuid) 优先，列表节点可能缺省 -> 复合键兜底。
                rid = str(n.get("event_id") or n.get("EventId") or "").strip()
                key = rid or "|".join(str(n.get(k) or "") for k in
                                      ("created_at", "src_ip", "url_path",
                                       "dst_port"))
                if not key or key == "|||":
                    key = rid or str(n.get("id") or "")
                if not key:
                    continue
                created = n.get("created_at")
                ts = None
                if isinstance(created, (int, float)) and created > 0:
                    ts = datetime.fromtimestamp(
                        created).strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(created, str) and created:
                    ts = created
                cur = conn.execute(
                    "INSERT OR IGNORE INTO events"
                    "(safeline_id, resource_id, ts, src_ip, host, port, uri,"
                    " attack_type, policy_name, payload, raw, created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        key,
                        rid or None,
                        ts,
                        str(n.get("src_ip") or ""),
                        n.get("host"),
                        n.get("dst_port"),
                        n.get("url_path"),
                        n.get("rule_id"),
                        n.get("policy_name"),
                        n.get("payload") or n.get("query_string"),
                        json.dumps(n, ensure_ascii=False),
                        _now(),
                    ),
                )
                if cur.rowcount > 0:
                    new_ids.append(cur.lastrowid)
            conn.commit()
        finally:
            conn.close()
    return new_ids, None


def pending_analyses(batch=4, delay_seconds=0):
    """取出已过研判延迟、尚未研判的事件。"""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM events WHERE analyzed=0 "
            "AND created_at<=datetime('now','localtime',? ) "
            "ORDER BY id LIMIT ?",
            ("-%d seconds" % delay_seconds, batch),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def save_analysis(event_id, a):
    with _lock:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO analyses"
                "(event_id, verdict, confidence, variant, suggested_rule,"
                " explain, model, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    a.get("verdict", "unknown"),
                    float(a.get("confidence") or 0.0),
                    a.get("variant"),
                    a.get("suggested_rule"),
                    a.get("explain"),
                    a.get("model"),
                    _now(),
                ),
            )
            conn.execute("UPDATE events SET analyzed=1 WHERE id=?", (event_id,))
            conn.commit()
        finally:
            conn.close()


def list_events(limit=50, offset=0):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT e.*, a.verdict, a.confidence, a.variant AS ai_variant "
            "FROM events e LEFT JOIN analyses a ON a.id="
            "(SELECT MAX(id) FROM analyses WHERE event_id=e.id) "
            "ORDER BY e.id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_analyses(limit=30):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT a.*, e.uri, e.attack_type, e.src_ip "
            "FROM analyses a JOIN events e ON e.id=a.event_id "
            "ORDER BY a.id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def events_payloads_since(event_id, limit=5000):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, uri, payload, attack_type FROM events "
            "WHERE id>? ORDER BY id LIMIT ?",
            (event_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------- rules ----------------

def add_rule(name, regex, site_id, host, uri_prefix, observed_until,
             safeline_policy_id, confidence, source="ai-closed-loop", sample=""):
    with _lock:
        conn = get_conn()
        try:
            cur = conn.execute(
                "INSERT INTO rules"
                "(name, regex, site_id, host, uri_prefix, status,"
                " observed_until, safeline_policy_id, confidence, source,"
                " sample, created_at, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (name, regex, site_id, host, uri_prefix, "observing",
                 observed_until, safeline_policy_id, confidence, source,
                 sample, _now(), _now()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def all_rules():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM rules ORDER BY id").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def active_rules():
    """仍在雷池生效的规则（未合并、未回收）。"""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM rules WHERE status IN ('observing','promoted','pending_review') "
            "AND merged_into IS NULL ORDER BY id",
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_rule(rule_id, **fields):
    if not fields:
        return
    fields["updated_at"] = _now()
    cols = ",".join("%s=?" % k for k in fields)
    with _lock:
        conn = get_conn()
        try:
            conn.execute(
                "UPDATE rules SET %s WHERE id=?" % cols,
                tuple(fields.values()) + (rule_id,),
            )
            conn.commit()
        finally:
            conn.close()


def rule_regex_exists(regex):
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT id FROM rules WHERE regex=? "
            "AND status IN ('observing','promoted') AND merged_into IS NULL",
            (regex,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def list_rules_by_status(status):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM rules WHERE status=? AND merged_into IS NULL ORDER BY id",
            (status,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_ai_rules():
    """所有 AI 闭环生成、仍在雷池生效的规则（用于批量回滚）。"""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM rules WHERE source='ai-closed-loop' "
            "AND status IN ('observing','promoted','pending_review') "
            "AND merged_into IS NULL ORDER BY id",
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------- 正常流量池（转正前零误杀回放用） ----------------

def add_normal(text, host="", uri="", src_ip=""):
    """把一条"确认正常"的请求写入正常流量池（按内容 md5 去重）。

    超出 NORMAL_POOL_MAX 时淘汰最旧的，防止无限增长。
    返回 True 表示新写入，False 表示重复或空。
    """
    text = (text or "").strip()
    if not text:
        return False
    dedup = hashlib.md5(text.encode("utf-8")).hexdigest()
    with _lock:
        conn = get_conn()
        try:
            cur = conn.execute(
                "INSERT OR IGNORE INTO normal_pool"
                "(dedup, text, host, uri, src_ip, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (dedup, text, host or "", uri or "", src_ip or "", _now()),
            )
            if cur.rowcount > 0:
                conn.execute(
                    "DELETE FROM normal_pool WHERE id NOT IN "
                    "(SELECT id FROM normal_pool ORDER BY id DESC LIMIT ?)",
                    (config.NORMAL_POOL_MAX,),
                )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def normal_pool_texts(limit=0):
    """返回正常流量池的文本列表（回放匹配对象，含完整 uri/query）。"""
    conn = get_conn()
    try:
        if limit:
            rows = conn.execute(
                "SELECT text FROM normal_pool ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT text FROM normal_pool ORDER BY id").fetchall()
        return [r["text"] for r in rows]
    finally:
        conn.close()


def normal_pool_count():
    conn = get_conn()
    try:
        return conn.execute(
            "SELECT COUNT(*) c FROM normal_pool").fetchone()["c"]
    finally:
        conn.close()


# ---------------- stats ----------------

def stats():
    conn = get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        analyzed = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE analyzed=1").fetchone()["c"]
        attacks = conn.execute(
            "SELECT COUNT(*) c FROM analyses WHERE verdict='attack'").fetchone()["c"]
        observing = conn.execute(
            "SELECT COUNT(*) c FROM rules "
            "WHERE status='observing' AND merged_into IS NULL").fetchone()["c"]
        promoted = conn.execute(
            "SELECT COUNT(*) c FROM rules "
            "WHERE status='promoted' AND merged_into IS NULL").fetchone()["c"]
        recycled = conn.execute(
            "SELECT COUNT(*) c FROM rules WHERE status='recycled'").fetchone()["c"]
        hits = conn.execute(
            "SELECT COALESCE(SUM(hits),0) c FROM rules").fetchone()["c"]
        return {
            "total_events": total,
            "analyzed": analyzed,
            "attack_verdicts": attacks,
            "rules_observing": observing,
            "rules_promoted": promoted,
            "rules_recycled": recycled,
            "rules_hits": hits,
        }
    finally:
        conn.close()