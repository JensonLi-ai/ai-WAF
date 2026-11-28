"""AI-WAF 控制面板（stdlib http.server + 原生 JS 单页，无外部依赖）。"""
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import config, db

ENGINE = None  # 由 main 注入，供审批/回滚端点调用

PAGE = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-WAF 闭环面板</title>
<style>
:root{--bg:#0b1220;--card:#121b2e;--line:#22304d;--tx:#dbe6ff;--dim:#7e92b8;
--ok:#35d07f;--warn:#f5b942;--bad:#ff5c6c;--acc:#4da3ff;--mono:Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font:14px/1.6 "Segoe UI",system-ui,sans-serif}
header{padding:18px 26px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:14px;flex-wrap:wrap}
header h1{font-size:18px;letter-spacing:1px}
header .tag{color:var(--dim);font-size:12px;font-family:var(--mono)}
.cards{display:flex;gap:14px;padding:18px 26px;flex-wrap:wrap}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:14px 22px;min-width:130px}
.card b{display:block;font-size:26px;font-family:var(--mono)}
.card span{color:var(--dim);font-size:12px}
main{padding:0 26px 30px}
section{margin-bottom:22px}
h2{font-size:14px;color:var(--acc);margin:14px 0 8px;letter-spacing:1px}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:12.5px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--dim);font-weight:600;background:#0e1626}
tr:last-child td{border-bottom:none}
.mono{font-family:var(--mono)}
.pill{display:inline-block;padding:1px 9px;border-radius:10px;font-size:11px;
border:1px solid var(--line)}
.v-attack{color:var(--bad);border-color:var(--bad)}
.v-benign{color:var(--ok);border-color:var(--ok)}
.v-unknown{color:var(--warn);border-color:var(--warn)}
.s-observing{color:var(--warn)} .s-promoted{color:var(--ok)}
.s-recycled{color:var(--dim)}
.regex{font-family:var(--mono);color:#9fd0ff;word-break:break-all}
footer{color:var(--dim);padding:10px 26px 30px;font-size:12px}
</style></head><body>
<header><h1>AI-WAF</h1>
<span class="tag">模式 %RUNMODE% · 面板端口 %PORT%</span></header>
<div class="cards" id="cards"></div>
<main>
<section><h2>AI 规则库（生命周期：观察期→转正→回收，上限 300）
<button onclick="rollback()" style="float:right;font-size:12px;padding:4px 10px;background:#ff5c6c;color:#fff;border:0;border-radius:6px;cursor:pointer">批量禁用 AI 规则</button></h2>
<table><thead><tr><th>ID</th><th>名称</th><th>正则</th><th>状态</th><th>命中</th>
<th>置信度</th><th>来源</th><th>作用域</th><th>到期</th><th>雷池ID</th><th>操作</th></tr></thead>
<tbody id="rules"><tr><td colspan="11">加载中…</td></tr></tbody></table></section>
<section><h2>攻击事件与 AI 研判</h2>
<table><thead><tr><th>#</th><th>时间</th><th>源IP</th><th>域名</th><th>URI</th>
<th>类型</th><th>研判</th><th>置信度</th><th>解释</th></tr></thead>
<tbody id="events"><tr><td colspan="9">加载中…</td></tr></tbody></table></section>
</main>
<footer>AI 研判结果与规则自动下发记录仅供参考，生产环境请切换官方 OpenAPI Key。</footer>
<script>
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,
 c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pill={attack:'v-attack',benign:'v-benign',unknown:'v-unknown'};
async function api(url,opt){
 opt=opt||{};const h=Object.assign({},opt.headers||{});
 const t=localStorage.getItem('aiwaf_token')||'';if(t)h['X-Auth-Token']=t;
 opt.headers=h;let r=await fetch(url,opt);
 if(r.status===401){
  const t2=prompt('请输入面板访问令牌（WEB_AUTH_TOKEN）');
  if(t2){localStorage.setItem('aiwaf_token',t2);return api(url,opt);}
  throw new Error('unauthorized');
 }
 return r;
}
async function load(){
 try{
  const [st,rl,ev]=await Promise.all([
   api('/api/stats').then(r=>r.json()),
   api('/api/rules').then(r=>r.json()),
   api('/api/events?limit=40').then(r=>r.json())]);
  const cards=[['事件总数',st.total_events],['已研判',st.analyzed],
   ['攻击判定',st.attack_verdicts],['观察期规则',st.rules_observing],
   ['已转正规则',st.rules_promoted],['已回收',st.rules_recycled],
   ['规则累计命中',st.rules_hits],['模型生成规则',(st.rules_by_source||{}).model||0],
   ['缓存命中',st.cache_hits||0]];
  document.getElementById('cards').innerHTML=cards.map(([n,v])=>
   `<div class="card"><b>${esc(v)}</b><span>${esc(n)}</span></div>`).join('');
  document.getElementById('rules').innerHTML=(rl.length?rl.map(r=>
   `<tr><td>${r.id}</td><td class="mono">${esc(r.name)}</td>
   <td class="regex">${esc(r.regex)}</td>
   <td class="s-${esc(r.status)}">${esc(r.status)}</td>
   <td>${r.hits}</td><td>${(+r.confidence).toFixed(2)}</td>
   <td class="mono">${esc(r.regex_source||'-')}</td>
   <td class="mono">${esc(r.uri_prefix||'-')} @ ${esc(r.host||r.site_id||'-')}</td>
   <td class="mono">${esc(r.observed_until||'')}</td>
   <td>${r.safeline_policy_id??''}</td>
   <td>${r.status==='pending_review'?`<button onclick="approve(${r.id})">批准</button>`:''}</td></tr>`).join('')
  :`<tr><td colspan="11">暂无 AI 规则</td></tr>`);
  document.getElementById('events').innerHTML=(ev.length?ev.map(e=>
   `<tr><td>${e.safeline_id}</td><td class="mono">${esc(e.ts)}</td>
   <td class="mono">${esc(e.src_ip)}</td><td>${esc(e.host)}</td>
   <td class="mono">${esc(e.uri)}</td><td>${esc(e.attack_type)}</td>
   <td><span class="pill ${pill[e.verdict]||'v-unknown'}">${esc(e.verdict||'待研判')}</span></td>
   <td>${e.confidence? (+e.confidence).toFixed(2):'-'}</td>
   <td>${esc((e.explain||'').slice(0,80))}</td></tr>`).join('')
  :`<tr><td colspan="9">暂无事件</td></tr>`);
 }catch(err){document.getElementById('cards').textContent='接口异常: '+err}
}
async function approve(id){await api('/api/rules/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});load()}
async function rollback(){if(!confirm('确认批量禁用所有 AI 规则？'))return;await api('/api/rules/rollback',{method:'POST',headers:{'Content-Type':'application/json'}});load()}
load();setInterval(load,10000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass  # 客户端先断开（如回滚耗时较长）不应打印堆栈

    def _html(self, text):
        data = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def _token_ok(self):
        """配置了 WEB_AUTH_TOKEN 时，校验 X-Auth-Token / ?token=。"""
        token = config.WEB_AUTH_TOKEN
        if not token:
            return True
        given = self.headers.get("X-Auth-Token") or ""
        if not given:
            qs = parse_qs(urlparse(self.path).query)
            given = (qs.get("token") or [""])[0]
        return hmac.compare_digest(given, token)

    def _same_origin(self):
        """存在 Origin 时必须与 Host 一致，阻断跨站提交。"""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        return urlparse(origin).netloc == (self.headers.get("Host") or "")

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            return self._html(PAGE.replace("%PORT%", str(config.WEB_PORT))
                              .replace("%RUNMODE%", config.RUN_MODE))
        if u.path == "/api/health":
            return self._json({"ok": True, "run_mode": config.RUN_MODE,
                               "engine": ENGINE is not None})
        if not self._token_ok():
            return self._json({"err": "unauthorized"}, 401)
        if u.path == "/api/metrics":
            m = ENGINE.metrics_snapshot() if ENGINE is not None else {}
            m.update(db.stats())
            return self._json(m)
        if u.path == "/api/stats":
            return self._json(db.stats())
        if u.path == "/api/events":
            limit = min(int(qs.get("limit", ["50"])[0]), 500)
            return self._json(db.list_events(limit=limit))
        if u.path == "/api/analyses":
            return self._json(db.list_analyses())
        if u.path == "/api/rules":
            return self._json(db.all_rules())
        self._json({"err": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        if not self._token_ok():
            return self._json({"err": "unauthorized"}, 401)
        if not self._same_origin():
            return self._json({"err": "cross-origin rejected"}, 403)
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            # 只接受 JSON：HTML 表单无法伪造该 Content-Type，阻断简单 CSRF
            return self._json({"err": "content-type must be application/json"}, 415)
        ln = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(ln) or b"{}")
        except (ValueError, TypeError):
            body = {}
        if u.path == "/api/rules/approve":
            if ENGINE is None:
                return self._json({"err": "engine not available"}, 500)
            rid = int(body.get("id") or 0)
            return self._json({"ok": ENGINE.approve_rule(rid)})
        if u.path == "/api/rules/rollback":
            if ENGINE is None:
                return self._json({"err": "engine not available"}, 500)
            return self._json({"ok": True,
                               "disabled": ENGINE.rollback_ai_rules()})
        self._json({"err": "not found"}, 404)

    def log_message(self, *args):
        pass


def serve(engine=None):
    global ENGINE
    ENGINE = engine
    if not config.WEB_AUTH_TOKEN and config.WEB_HOST not in (
            "127.0.0.1", "localhost", "::1"):
        raise SystemExit(
            "拒绝启动：WEB_HOST=%s 非回环地址时必须设置 WEB_AUTH_TOKEN" %
            config.WEB_HOST)
    httpd = ThreadingHTTPServer((config.WEB_HOST, config.WEB_PORT), Handler)
    httpd.daemon_threads = True
    print("AI-WAF panel: http://%s:%d" % (config.WEB_HOST, config.WEB_PORT),
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass