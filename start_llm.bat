@echo off
cd /d "H:\AIWAF\backend\extensions\backends\llama.cpp-win-x86_64-nvidia-cuda12-avx2-2.30.0"
echo [AI-WAF] Starting Qwen3-14B on http://127.0.0.1:1234 ...
echo          (close this window to stop the service)
llama-server.exe --model "H:\AIWAF\lmstudio\models\Qwen\qwen3-14b-abliterated\qwen3-14b-abliterated-Q4_K_M.gguf" --host 127.0.0.1 --port 1234 -c 16384 -ngl 999