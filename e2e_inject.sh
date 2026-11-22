#!/bin/bash
TOKEN="${SAFELINE_TOKEN:?请先设置环境变量 SAFELINE_TOKEN}"
echo "== one full list record =="
curl -sk -m 10 "https://localhost:9443/api/open/records?page=1&page_size=1" -H "Authorization: Bearer $TOKEN"
echo
echo "== records page_size=100 total? =="
curl -sk -m 10 "https://localhost:9443/api/open/records?page=1&page_size=100" -H "Authorization: Bearer $TOKEN" | head -c 200; echo