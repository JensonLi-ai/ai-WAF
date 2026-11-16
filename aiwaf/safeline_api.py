"""雷池控制台 API 客户端。

架构约定（见 project_memory）：接口层抽象为 SafelineClient，engine 只依赖
抽象方法；生产环境新增 OpenApiKeySafelineClient 子类（官方 OpenAPI Key，
端点 open/auth/token）即可切换，业务逻辑零改动。

已实测打通的接口（社区版 9.x）：
- GET  /api/open/events               攻击日志（分页 + 过滤）
- GET  /api/open/record/<id>          单条事件详情（payload 等）
- GET  /api/open/policy               自定义规则列表
- POST /api/open/policy               创建规则（body 必须含 insert_position）
- PUT  /api/open/policy               全量更新规则（body 含 id）
- PUT  /api/open/policy/switch        启用/停用 {id, is_enabled}
- DELETE /api/open/policy             删除 {"id": N}
"""
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod

from . import config


class SafelineError(Exception):
    def __init__(self, status, url, msg):
        self.status = status
        self.url = url
        self.msg = msg
        super().__init__("safeline %s %s -> HTTP %s: %s" % (url, status, status, msg))


def _ssl_ctx():
    if config.SSL_VERIFY:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class SafelineClient(ABC):
    """雷池接口抽象：engine 只面向这个接口编程。"""

    @abstractmethod
    def list_events(self, page=1, page_size=100, start=None, end=None,
                    ip=None, host=None, port=None):
        """返回攻击日志页：{"nodes": [...], "total": N}"""

    @abstractmethod
    def get_record(self, event_id):
        """返回单条事件详情 dict"""

    @abstractmethod
    def list_policies(self, page=1, page_size=50, action=-1):
        """返回自定义规则数组"""

    @abstractmethod
    def create_policy(self, name, conditions, is_enabled=True, action=1,
                      log=False, insert_position="first"):
        """创建规则，返回 policy id"""

    @abstractmethod
    def update_policy(self, policy):
        """全量更新规则（policy 为含 id 的完整策略 dict）"""

    @abstractmethod
    def switch_policy(self, policy_id, is_enabled):
        pass

    @abstractmethod
    def delete_policy(self, policy_id):
        pass


class JwtSafelineClient(SafelineClient):
    """原型实现：控制台会话 JWT（仅原型验证，生产切 OpenAPI Key）。"""

    def __init__(self, base=None, token=None):
        self.base = (base or config.SAFELINE_BASE).rstrip("/")
        self.token = token or config.SAFELINE_TOKEN

    # ---- HTTP 基础 ----

    def _auth_headers(self):
        return {"Authorization": "Bearer " + self.token}

    def _request(self, method, path, body=None):
        url = self.base + path
        data = None
        headers = self._auth_headers()
        headers["Accept"] = "application/json"
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=30,
                                        context=_ssl_ctx()) as resp:
                text = resp.read().decode("utf-8", "replace")
                return json.loads(text) if text.strip() else None
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            raise SafelineError(e.code, url, text[:500]) from e
        except urllib.error.URLError as e:
            raise SafelineError(0, url, str(e.reason)) from e

    # ---- 攻击日志 ----

    def list_events(self, page=1, page_size=100, start=None, end=None,
                    ip=None, host=None, port=None):
        q = urllib.parse.urlencode({
            "page": page, "page_size": page_size,
            "start": start or "", "end": end or "",
            "ip": ip or "", "host": host or "", "port": port or "",
        })
        resp = self._request("GET", "/api/open/events?%s" % q)
        data = (resp or {}).get("data") or {}
        return {"nodes": data.get("nodes") or [], "total": data.get("total", 0)}

    def get_record(self, event_id):
        resp = self._request("GET", "/api/open/record/%s" % event_id)
        return (resp or {}).get("data") or {}

    def list_records(self, page=1, page_size=100):
        """攻击日志记录（细粒度，含 url_path/rule_id/query_string 等）。"""
        q = urllib.parse.urlencode(
            {"page": page, "page_size": page_size})
        resp = self._request("GET", "/api/open/records?%s" % q)
        data = (resp or {}).get("data") or {}
        if isinstance(data, dict):
            return {"records": data.get("data") or [],
                    "total": data.get("total", 0)}
        return {"records": data or [], "total": len(data or [])}

    # ---- 自定义规则 ----

    def list_policies(self, page=1, page_size=50, action=-1):
        q = urllib.parse.urlencode(
            {"page": page, "page_size": page_size, "action": action})
        resp = self._request("GET", "/api/open/policy?%s" % q)
        data = (resp or {}).get("data") or {}
        if isinstance(data, dict):
            return data.get("data") or []
        return data or []

    def build_conditions(self, uri_regex=None, host=None, site_id=None):
        """构造规则条件树。

        实测格式：pattern 为二维数组——外层列表是 OR 组，内层是 AND 条件，
        每项 {k, op, v(list), sub_k}。扁平列表会 400 "Error occurred
        when extracting params"。
        硬约束：AI 规则必须绑定站点 ID（或域名 host 等价收敛匹配范围）
        与 URI 路径前缀，防止规则无限匹配。
        """
        conds = []
        if site_id:
            conds.append({"k": "website", "op": "in",
                          "v": [str(site_id)], "sub_k": ""})
        if host:
            conds.append({"k": "host", "op": "eq", "v": [host], "sub_k": ""})
        if uri_regex:
            # 实测（probe_ops 穷举）：uri 正则条件 op 必须为 "re"；
            # "match"/"in" 会被引擎按恒真处理 → 规则无条件拦截全部流量
            conds.append({"k": "uri", "op": "re",
                          "v": [uri_regex], "sub_k": ""})
        return [conds] if conds else []

    def create_policy(self, name, conditions, is_enabled=True, action=1,
                      log=False, insert_position="first"):
        # 实测教训：pattern 必须是二维数组（外层 OR 组），且
        # auth_source_ids / insert_position 缺一即 400
        body = {
            "name": name,
            "is_enabled": is_enabled,
            "pattern": conditions,
            "auth_source_ids": [],
            "action": action,
            "log": log,
            "insert_position": insert_position,
        }
        resp = self._request("POST", "/api/open/policy", body)
        return (resp or {}).get("data")

    def update_policy(self, policy):
        self._request("PUT", "/api/open/policy", policy)

    def switch_policy(self, policy_id, is_enabled):
        self._request("PUT", "/api/open/policy/switch",
                      {"id": policy_id, "is_enabled": is_enabled})

    def delete_policy(self, policy_id):
        self._request("DELETE", "/api/open/policy", {"id": policy_id})


class OpenApiKeySafelineClient(JwtSafelineClient):
    """生产实现：官方 OpenAPI Token（社区版 ≥ 6.6.0）。

    认证走自定义头 X-SLCE-API-TOKEN（而非 Bearer JWT），Token 在雷池
    管理后台「系统设置 → API Token」生成，不设过期时间即永久有效。
    其余接口与业务逻辑完全一致，仅认证头不同。
    """

    def __init__(self, base=None, token=None):
        self.base = (base or config.SAFELINE_BASE).rstrip("/")
        self.token = token or config.SAFELINE_OPENAPI_TOKEN

    def _auth_headers(self):
        return {"X-SLCE-API-TOKEN": self.token}