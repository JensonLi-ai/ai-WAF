"""本地 llama-server（OpenAI 兼容接口）客户端。

工程约定：用 llama.cpp 的 JSON grammar（GBNF）强制模型输出合法 JSON，
优于失败重试。config.LLM_GRAMMAR：
- "builtin"（默认）: 使用内置通用 JSON grammar
- ""              : 关闭 grammar
- 文件路径        : 使用自定义 GBNF 文件
"""
import json
import os
import re
import urllib.error
import urllib.request

from . import config

# 专用研判 JSON grammar：强制输出全部 5 个字段。
# （通用 json.gbnf 允许空对象 {}，14B 小模型会"偷懒"直接输出 {} 就 stop）
# 注意：规则名不能用下划线——LM Studio 自带 llama.cpp 的 GBNF 解析器不认。
ANALYSIS_GBNF = r"""
root ::= "{" ws kvverdict "," ws kvvariant "," ws kvconfidence "," ws kvsuggested "," ws kvexplain ws "}" ws
kvverdict ::= "\"verdict\"" ws ":" ws verdict
kvvariant ::= "\"variant\"" ws ":" ws string
kvconfidence ::= "\"confidence\"" ws ":" ws number
kvsuggested ::= "\"suggested_rule\"" ws ":" ws string
kvexplain ::= "\"explain\"" ws ":" ws string
verdict ::= "\"attack\"" | "\"benign\"" | "\"unknown\""
string ::=
  "\"" (
    [^"\\] |
    "\\" (["\\/bfnrt] | "u" [0-9a-fA-F] [0-9a-fA-F] [0-9a-fA-F] [0-9a-fA-F])
  )* "\"" ws
number ::= ("-"? ([0-9] | [1-9] [0-9]*)) ("." [0-9]+)? ([eE] [-+]? [0-9]+)? ws
ws ::= ([ \t\n] ws)?
"""

SYSTEM_PROMPT = """你是 WEB 应用防火墙（WAF）的 AI 研判引擎。分析给定的攻击事件（JSON），
只输出一个 JSON 对象（固定 5 字段），禁止任何额外文字、注释、代码围栏。

判断标准：
- verdict: attack（真实攻击）/ benign（正常请求）/ unknown（无法判断）
- variant: 仅当该攻击是雷池语义引擎难以识别的新颖/变形攻击时，给一个简短
  命名（如 xss_svg_onload_var）；常见已知攻击或正常请求则留空字符串 ""
- confidence: 0~1 的置信度，越接近 1 越确信是攻击
- suggested_rule: 仅当高置信度且属于新颖变种时，给一条 Python re 兼容正则，
  尽量具体只匹配该攻击特征，禁止 .* 大范围通配；必须能匹配输入 payload 里的
  真实片段，且反斜杠等特殊字符需双重转义；否则留空 ""
- explain: 一句中文结论

严格模仿下列三个示例的判断口径与措辞：
例1（变形攻击）：
输入：{"host":"demo.test","uri":"/?q=<svg onload=alert(1)>","payload":"<svg onload=alert(1)>"}
输出：{"verdict":"attack","variant":"xss_svg_onload_var","confidence":0.97,"suggested_rule":"<svg[^>]*\\sonload\\s*=","explain":"SVG 标签携带 onload 事件，属变形 XSS，固定关键词规则易漏判"}

例2（正常请求）：
输入：{"host":"demo.test","uri":"/?q=hello%20world","payload":"hello world"}
输出：{"verdict":"benign","variant":"","confidence":0.99,"suggested_rule":"","explain":"普通文本参数，无攻击特征"}

例3（命令注入变种）：
输入：{"host":"demo.test","uri":"/?cmd=|id","payload":"|id"}
输出：{"verdict":"attack","variant":"cmdi_pipe_var","confidence":0.96,"suggested_rule":"\\|\\s*(id|whoami|cat)\\b","explain":"管道符注入命令，属命令注入变种"}

例4（时间盲注）：
输入：{"host":"demo.test","uri":"/?id=1 AND sleep(5)","payload":"1 AND sleep(5)"}
输出：{"verdict":"attack","variant":"sqli_time_based","confidence":0.95,"suggested_rule":"\\bsleep\\s*\\(","explain":"sleep 延时注入，属时间盲注"}

例5（路径穿越）：
输入：{"host":"demo.test","uri":"/?file=../../etc/passwd","payload":"../../etc/passwd"}
输出：{"verdict":"attack","variant":"path_traversal","confidence":0.96,"suggested_rule":"\\.\\./.*(etc/passwd|win.ini)","explain":"目录穿越读取敏感文件"}

例6（SSRF 云元数据）：
输入：{"host":"demo.test","uri":"/?url=http://169.254.169.254/latest/meta-data/","payload":"http://169.254.169.254/latest/meta-data/"}
输出：{"verdict":"attack","variant":"ssrf_metadata","confidence":0.95,"suggested_rule":"169\\.254\\.169\\.254|/latest/meta-data","explain":"访问云元数据地址，属 SSRF"}

容易误判的正常请求（必须判 benign，不要只看关键词）：
例7（单独关键词搜索）：
输入：{"host":"demo.test","uri":"/?q=sleep","payload":"sleep"}
输出：{"verdict":"benign","variant":"","confidence":0.95,"suggested_rule":"","explain":"单独的单词搜索，无函数调用或注入语法，属正常请求"}

例8（站内登录跳转）：
输入：{"host":"demo.test","uri":"/admin/login?redirect=/dashboard","payload":"redirect=/dashboard"}
输出：{"verdict":"benign","variant":"","confidence":0.95,"suggested_rule":"","explain":"站内登录跳转，redirect 指向站内路径，无 SSRF 构造"}

例9（业务 JWT 参数）：
输入：{"host":"demo.test","uri":"/?auth=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig","payload":"auth=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig"}
输出：{"verdict":"benign","variant":"","confidence":0.95,"suggested_rule":"","explain":"正常业务 JWT 认证参数，三段结构完整，无注入特征"}

判断原则：关键词不等于攻击。只有看到能构成注入/执行的语法结构（引号闭合注入、管道符、模板表达式、DOCTYPE 实体、序列化头等）才判 attack；只有关键词但无语境判 benign；确实拿不准判 unknown。suggested_rule 必须是合法 Python re 正则，JSON 内反斜杠一律写成双反斜杠 \\\\，禁止以反斜杠结尾。"""


# 模型想输出正则里的 \b（词边界）/ \f 等，但若在 JSON 字符串里只写单反斜杠，
# json.loads 会按 JSON 转义把它变成控制字符（\b=0x08 退格、\f=0x0c 换页…），
# 导致规则变成含控制字符的非法片段、被样本守卫丢弃。这里还原成对应的正则转义。
_CTRL_TO_ESCAPE = {
    "\x08": r"\b", "\x0c": r"\f", "\x09": r"\t",
    "\x0a": r"\n", "\x0d": r"\r",
}


def _fix_regex_escapes(r):
    if not r:
        return r
    for ch, esc in _CTRL_TO_ESCAPE.items():
        r = r.replace(ch, esc)
    return r


class LlmError(Exception):
    pass


def _load_grammar():
    cfg = config.LLM_GRAMMAR
    if cfg in (None, ""):
        return None
    if cfg == "builtin":
        return ANALYSIS_GBNF
    if os.path.isfile(cfg):
        with open(cfg, "r", encoding="utf-8") as f:
            return f.read()
    return cfg  # 直接当 GBNF 文本用


class LlmClient:
    def __init__(self, base=None, model=None):
        self.base = (base or config.LLM_BASE).rstrip("/")
        self.model = model or config.LLM_MODEL
        self.grammar = _load_grammar()

    def _chat(self, user_prompt):
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": config.LLM_TEMP,
            "stream": False,
            "max_tokens": config.LLM_MAX_TOKENS,
        }
        if self.grammar:
            body["grammar"] = self.grammar
        req = urllib.request.Request(
            self.base + "/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            raise LlmError("llm HTTP %s: %s" % (e.code, text[:300])) from e
        except urllib.error.URLError as e:
            raise LlmError("llm connect failed: %s" % e.reason) from e
        except TimeoutError as e:
            raise LlmError("llm timeout: %s" % e) from e

    @staticmethod
    def _parse_content(content):
        """尽量解析出 JSON：宽容转义 -> 直接 parse -> 去代码围栏 -> 截取首个 {...}"""
        text = (content or "").strip()
        # 模型常把正则里的 \d \s 写成 JSON 单反斜杠（非法 JSON 转义），
        # 导致整个 JSON 解析失败；先补成双反斜杠救回这批输出。
        # 注意 (?<!\\) 约束：不能把合法转义对 \\ 的第二个反斜杠误判为非法。
        text = re.sub(r'(?<!\\)\\(?!["\\/bfnrtu])', r"\\\\", text)
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            pass
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
        if m:
            try:
                return json.loads(m.group(1))
            except ValueError:
                pass
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except ValueError:
                pass
        return None

    def analyze(self, event):
        """研判单条事件，返回规范化 dict。

        无论模型输出如何都返回合法结构（verdict/confidence 有兜底），
        不抛异常——单条研判失败不应拖垮整个轮询循环。
        """
        try:
            event_json = json.dumps(event, ensure_ascii=False)
            # 控制上下文长度，超长 payload 截断
            if len(event_json) > 8000:
                event = dict(event)
                payload = event.get("payload") or event.get("raw")
                if isinstance(payload, str) and len(payload) > 4000:
                    event["payload"] = payload[:4000] + "...(截断)"
                event_json = json.dumps(event, ensure_ascii=False)
            resp = self._chat("攻击事件：\n" + event_json)
            content = (resp.get("choices") or [{}])[0] \
                .get("message", {}).get("content", "")
            obj = self._parse_content(content)
        except LlmError as e:
            return {"verdict": "unknown", "confidence": 0.0,
                    "variant": None, "suggested_rule": None,
                    "explain": str(e), "model": self.model,
                    "_error": True}
        if not isinstance(obj, dict):
            return {"verdict": "unknown", "confidence": 0.0,
                    "variant": None, "suggested_rule": None,
                    "explain": "模型输出非 JSON", "model": self.model,
                    "_error": True}
        verdict = str(obj.get("verdict", "unknown")).strip().lower()
        if verdict not in ("attack", "benign", "unknown"):
            verdict = "unknown"
        try:
            confidence = float(obj.get("confidence") or 0.0)
            confidence = max(0.0, min(1.0, confidence))
        except (TypeError, ValueError):
            confidence = 0.0
        return {
            "verdict": verdict,
            "confidence": confidence,
            "variant": obj.get("variant") or None,
            "suggested_rule": _fix_regex_escapes(obj.get("suggested_rule") or None),
            "explain": obj.get("explain") or "",
            "model": self.model,
        }