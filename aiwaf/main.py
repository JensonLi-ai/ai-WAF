"""AI-WAF 闭环管线入口：启动 engine 线程 + Web 面板。"""
import sys
import threading

from . import config, db, engine, llm_client, miss_collector, safeline_api, web


def main():
    print("AI-WAF starting: safeline=%s llm=%s db=%s" %
          (config.SAFELINE_BASE, config.LLM_BASE, config.DB_PATH), flush=True)
    db.init()
    if config.MISS_POLL_ENABLED:
        threading.Thread(target=miss_collector.serve, daemon=True,
                         name="miss-collector").start()
    if config.SAFELINE_AUTH_MODE == "openapi":
        safeline = safeline_api.OpenApiKeySafelineClient()
    else:
        safeline = safeline_api.JwtSafelineClient()
    llm = llm_client.LlmClient()
    eng = engine.Engine(safeline, llm)
    eng.start()
    web.serve(engine=eng)


if __name__ == "__main__":
    sys.exit(main())