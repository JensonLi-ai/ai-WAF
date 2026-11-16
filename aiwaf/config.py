"""AI-WAF 闭环管线 — 全局配置

原型阶段约定：
- 雷池接口走控制台 JWT（仅原型，生产切 OpenAPI Key，见 project_memory）
- llm 走本地 llama-server（OpenAI 兼容接口）
"""
import os

# ---- 雷池 WAF ----
SAFELINE_BASE = os.environ.get("SAFELINE_BASE", "https://localhost:9443")

# ---- 认证方式 ----
# "openapi" = 官方 OpenAPI Token（header: X-SLCE-API-TOKEN，生产用，永久有效）
# "jwt"     = 前端会话 JWT（Authorization: Bearer，仅原型，会随会话失效）
SAFELINE_AUTH_MODE = os.environ.get("SAFELINE_AUTH_MODE", "openapi")
SAFELINE_OPENAPI_TOKEN = os.environ.get("SAFELINE_OPENAPI_TOKEN", "")
SAFELINE_TOKEN = os.environ.get(
    "SAFELINE_TOKEN",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVaWQiOjEsIlVzZXJuYW1lIjoiYWRtaW4iLCJSb2xlIjoxLCJQd2QiOnRydWUsIlRmYSI6ZmFsc2UsIlZlciI6MH0.xS6I3lIJ4qrQcAbP7X3L53G6noq1IRBBm4GqyXOJvqg",
)
SAFELINE_PAGE_SIZE = 100          # 拉取攻击日志每页条数
SSL_VERIFY = False                # 雷池自签证书，原型阶段不校验证书

# ---- 本地 LLM (llama-server, OpenAI 兼容) ----
LLM_BASE = os.environ.get("LLM_BASE", "http://127.0.0.1:1234")
LLM_MODEL = os.environ.get("LLM_MODEL", "qwen3-14b")
LLM_TIMEOUT = 300
LLM_TEMP = 0.1
LLM_GRAMMAR = os.environ.get("LLM_GRAMMAR", "builtin")  # builtin=内置JSON grammar；空串=关闭；路径=自定义GBNF

# ---- 轮询 ----
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))     # 秒
ANALYZE_DELAY = int(os.environ.get("ANALYZE_DELAY", "5"))      # 事件拉回后延迟研判秒数(等日志齐)
MAINT_INTERVAL = int(os.environ.get("MAINT_INTERVAL", "3600")) # 规则生命周期维护周期(秒)

# ---- 规则生命周期（用户确认的硬约束） ----
OBSERVE_TTL_DAYS = 7                 # 观察期
PROMOTE_ZERO_HIT_DAYS = 14           # 转正后连续零命中回收天数
MAX_RULES = 300                      # 自定义规则硬上限
MIN_CONFIDENCE = 0.85                # 低于此置信度不生成规则
PROMOTE_THRESHOLD_HITS = 3           # 观察期命中次数阈值(转正参考)

# ---- 转正前零误杀回放（防误杀最后闸门） ----
# 规则观察期结束、准备转正拦截前，先用"已知正常流量池"回放一遍正则；
# 命中任意一条正常请求即判定会误杀，拒绝转正（回收该规则）。
PROMOTE_GUARD_ENABLED = os.environ.get("PROMOTE_GUARD_ENABLED", "1") == "1"
NORMAL_POOL_MIN = int(os.environ.get("NORMAL_POOL_MIN", "20"))     # 正常池至少 N 条才启用回放(太少无意义)
NORMAL_POOL_MAX = int(os.environ.get("NORMAL_POOL_MAX", "2000"))   # 正常池上限，超出淘汰最旧

# ---- 本地存储 ----
DB_PATH = os.environ.get("AIWAF_DB", os.path.join(os.path.dirname(__file__), "aiwaf.db"))

# ---- Web 面板 ----
WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "8899"))

# ---- 默认策略：AI 规则强制绑定站点与 URI 前缀（防止规则无限匹配） ----
DEFAULT_SITE_ID = os.environ.get("DEFAULT_SITE_ID", "")
REQUIRE_SITE_BINDING = True

# ---- 漏判检测（放行流量来源：旁路记录后端） ----
# 雷池社区版不记录放行流量、且 tengine 无 mirror 模块、access_log 被 t1k
# 拦截链路绕过。方案：在雷池 upstream 指向的真实后端（172.22.222.1:8088 =
# Windows 8088）起一个记录层服务，凡能到达的请求即雷池放行流量，逐条写
# JSONL；引擎增量读取作为漏判候选数据源。
MISS_POLL_ENABLED = os.environ.get("MISS_POLL_ENABLED", "1") == "1"
MISS_LOG_PATH = os.environ.get(
    "MISS_LOG_PATH",
    os.path.join(os.path.dirname(__file__), "miss_traffic.jsonl"))
MISS_COLLECTOR_HOST = os.environ.get("MISS_COLLECTOR_HOST", "0.0.0.0")
MISS_COLLECTOR_PORT = int(os.environ.get("MISS_COLLECTOR_PORT", "8088"))
MISS_MAX_BODY = int(os.environ.get("MISS_MAX_BODY", "65536"))  # 采集 body 上限(字节)
MISS_MAX_BATCH = int(os.environ.get("MISS_MAX_BATCH", "4"))