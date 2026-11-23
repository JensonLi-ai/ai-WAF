FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    WEB_HOST=0.0.0.0 \
    AIWAF_DB=/data/aiwaf.db \
    MISS_LOG_PATH=/data/miss_traffic.jsonl

COPY aiwaf ./aiwaf
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8899 8088
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8899/api/health',timeout=2)"

CMD ["python", "-m", "aiwaf.main"]
