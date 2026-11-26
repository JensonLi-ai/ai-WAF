"""一键启动引导：登录雷池、对齐站点 upstream，然后进入引擎主循环。

由 start_all.bat 调用（`python -m aiwaf.boot`）。小程序不做持久化凭据：
- 雷池控制台密码从环境变量 SAFELINE_PASSWORD 或
  %USERPROFILE%\\.aiwaf\\safeline.pwd 读取；
- 登录后拿到的 JWT 只保存在当前进程内存里。
"""
import base64
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request

from . import config


def _log(msg):
    print("[boot] %s" % msg, flush=True)


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(method, path, body=None, token=None):
    base = config.SAFELINE_BASE.rstrip("/")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_ctx()) as resp:
            text = resp.read().decode("utf-8", "replace")
            return json.loads(text) if text.strip() else None
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError("HTTP %s %s: %s" % (e.code, path, detail)) from e
    except urllib.error.URLError as e:
        raise RuntimeError("连接雷池失败 %s: %s" % (base, e.reason)) from e


def _password_file():
    return os.path.join(os.path.expanduser("~"), ".aiwaf", "safeline.pwd")


def _password():
    pwd = os.environ.get("SAFELINE_PASSWORD", "")
    if pwd:
        return pwd
    path = _password_file()
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""


def _login(password):
    """走雷池控制台的 AES + CSRF 登录流程，返回 JWT。"""
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise SystemExit(
            "[boot] 缺少 cryptography 依赖，请先执行：python -m pip install cryptography")

    key = (_request("GET", "/api/open/system/key") or {}).get("data")
    csrf = ((_request("GET", "/api/open/auth/csrf") or {}).get("data")
            or {}).get("csrf_token")
    if not key or not csrf:
        raise SystemExit("[boot] 雷池未就绪：拿不到登录参数（AES key / CSRF）")

    iv_hex = os.urandom(8).hex()
    padder = padding.PKCS7(128).padder()
    plain = padder.update(password.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(key.encode("utf-8")),
                 modes.CBC(iv_hex.encode("ascii")))
    e = enc.encryptor()
    cipher = e.update(plain) + e.finalize()

    body = {
        "username": os.environ.get("SAFELINE_USER", "admin"),
        "password": base64.b64encode(
            iv_hex.encode("ascii") + cipher).decode("ascii"),
        "csrf_token": csrf,
    }
    resp = _request("POST", "/api/open/auth/login", body) or {}
    jwt = (resp.get("data") or {}).get("jwt")
    if not jwt:
        raise SystemExit("[boot] 雷池登录失败，请检查账号密码：%s" % resp)
    return jwt


def _sync_upstream(jwt, wsl_ip, site_id=1):
    """把站点 upstream 对齐到 WSL 采集器地址（WSL IP 每次重启可能变化）。"""
    desired = "http://%s:8088" % wsl_ip
    site = (_request("GET", "/api/open/site/%d" % site_id, token=jwt)
            or {}).get("data") or {}
    if not site:
        _log("未找到站点 %d，跳过 upstream 同步" % site_id)
        return
    if desired in (site.get("upstreams") or []):
        _log("upstream 已对齐：%s" % desired)
        return
    body = {
        "id": site_id,
        "server_names": site.get("server_names") or ["*"],
        "ports": site.get("ports") or ["80"],
        "upstreams": [desired],
        "email": site.get("email") or "",
        "cert_id": site.get("cert_id") or 0,
        "comment": site.get("comment") or "",
        "type": site.get("type") or 0,
        "mode": site.get("mode") or 0,
        "load_balance": {
            "balance_type": 1,
            "upstreams": [{"address": desired, "weight": 1,
                           "role": "primary"}],
        },
    }
    _request("PUT", "/api/open/site", body, token=jwt)
    _log("upstream 已更新为 %s（原 %s）" % (desired, site.get("upstreams")))


def _engine_running():
    s = socket.socket()
    s.settimeout(0.5)
    try:
        return s.connect_ex((config.WEB_HOST, config.WEB_PORT)) == 0
    finally:
        s.close()


def main():
    if _engine_running():
        print("[boot] 引擎已在运行：http://%s:%d" %
              (config.WEB_HOST, config.WEB_PORT), flush=True)
        return 0

    pwd = _password()
    if not pwd:
        raise SystemExit(
            "[boot] 未找到雷池密码。请把 admin 密码写入：%s" % _password_file())

    jwt = _login(pwd)
    _log("雷池登录成功")

    wsl_ip = os.environ.get("AIWAF_WSL_IP", "").strip()
    if wsl_ip:
        try:
            _sync_upstream(jwt, wsl_ip)
        except Exception as e:
            _log("upstream 同步失败（不影响引擎启动）：%s" % e)

    config.SAFELINE_AUTH_MODE = "jwt"
    config.SAFELINE_TOKEN = jwt
    print("[boot] 启动引擎与面板 ...", flush=True)

    from .main import main as engine_main
    return engine_main()


if __name__ == "__main__":
    sys.exit(main())
