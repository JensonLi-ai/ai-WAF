"""LLM 客户端超时重试策略测试（不依赖真实模型）。"""
import unittest

from aiwaf import config
from aiwaf.llm_client import LlmClient, LlmError


class _FakeClient(LlmClient):
    def __init__(self):
        self.model = "fake"
        self.grammar = "builtin"
        self.calls = []

    def _chat(self, prompt, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) == 1:
            raise LlmError("llm timeout: timed out")
        return {"choices": [{"message": {"content": (
            '{"verdict":"attack","variant":"xss","confidence":0.97,'
            '"rule_anchors":["<svg","onload="],"suggested_rule":"",'
            '"explain":"test"}')}}]}


class TestTimeoutRetry(unittest.TestCase):
    def test_timeout_retry_uses_fast_path(self):
        c = _FakeClient()
        a = c.analyze({"payload": "<svg onload=alert(1)>"})
        self.assertEqual(a["verdict"], "attack")
        self.assertEqual(len(c.calls), 2)
        retry = c.calls[1]
        self.assertFalse(retry["use_grammar"])
        self.assertTrue(retry["disable_thinking"])
        self.assertEqual(retry["max_tokens"], config.LLM_RETRY_MAX_TOKENS)
        self.assertEqual(retry["timeout"], config.LLM_RETRY_TIMEOUT)

    def test_non_timeout_error_not_retried(self):
        class _Err(_FakeClient):
            def _chat(self, prompt, **kwargs):
                self.calls.append(kwargs)
                raise LlmError("llm HTTP 500: boom")

        c = _Err()
        a = c.analyze({"payload": "hello"})
        self.assertTrue(a.get("_error"))
        self.assertEqual(len(c.calls), 1)


if __name__ == "__main__":
    unittest.main()
