"""临时：用复活后的 JWT 跑通漏判闭环（含下发规则）"""
from aiwaf import config, db, engine, llm_client, safeline_api

db.init()
db.set_kv("miss_log_offset", "0")  # 重置游标重放旧样本
llm = llm_client.LlmClient()
safeline = safeline_api.JwtSafelineClient()  # Bearer + 复活的 JWT
eng = engine.Engine(safeline, llm)

cands = eng._extract_miss_candidates(eng._read_miss_log())
print("可疑候选数: %d" % len(cands))
for cand in cands:
    eng._analyze_miss(cand)

print("== 最新激活规则 ==")
for r in db.active_rules()[-3:]:
    print("  %s  status=%s  policy_id=%s  conf=%.2f" %
          (r["name"], r["status"], r["safeline_policy_id"], r["confidence"]))