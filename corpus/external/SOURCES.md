# 外部语料来源与许可

`attack_samples.jsonl` 由 `tools/build_external_corpus.py` 从以下公开项目抽取，
仅用于本地安全评测。样本版权归原作者，按 MIT 许可使用。

| 项目 | 许可 | 用途 |
|---|---|---|
| [SecLists](https://github.com/danielmiessler/SecLists) | MIT | SQLi / XSS / 命令注入 / 路径穿越 / SSTI / XXE / LDAP |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | MIT | SSRF / 反序列化 / NoSQL / CRLF / JNDI |

## 抽取规则

- 只做确定性行级抽取，不调用 LLM；
- 用类别特征正则过滤说明文字、文档命令、模板占位符；
- 每个来源按顺序等距采样，保证可复现；
- 每类最多 10 条，单条长度 3–300 字符；
- 生成后人工抽查过一轮，仍可能存在少量噪声。

## 当前规模

| 类别 | 条数 | 类别 | 条数 |
|---|---:|---|---:|
| sqli | 10 | xxe | 6 |
| xss | 10 | deser | 2 |
| cmdi | 10 | nosql | 7 |
| traversal | 10 | crlf | 2 |
| ssrf | 6 | ldap | 3 |
| ssti | 6 | jndi | 6 |

合计 78 条。deser / crlf / ldap 在公开列表中可用的纯 payload 较少，
这三类后续需要从 CVE 样本或专项测试集中补充。

## 重新生成

```bash
# 能直连 GitHub 时
python tools/build_external_corpus.py

# 需要代理时
HTTPS_PROXY=http://127.0.0.1:7897 python tools/build_external_corpus.py
```
