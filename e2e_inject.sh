#!/bin/bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVaWQiOjEsIlVzZXJuYW1lIjoiYWRtaW4iLCJSb2xlIjoxLCJQd2QiOnRydWUsIlRmYSI6ZmFsc2UsIlZlciI6MH0.xS6I3lIJ4qrQcAbP7X3L53G6noq1IRBBm4GqyXOJvqg"
echo "== one full list record =="
curl -sk -m 10 "https://localhost:9443/api/open/records?page=1&page_size=1" -H "Authorization: Bearer $TOKEN"
echo
echo "== records page_size=100 total? =="
curl -sk -m 10 "https://localhost:9443/api/open/records?page=1&page_size=100" -H "Authorization: Bearer $TOKEN" | head -c 200; echo