@echo off
chcp 936 >nul
title AI-WAF 一键恢复
setlocal

set "AIWAF_ROOT=C:\Users\Administrator\AppData\Roaming\Trae CN\ModularData\ai-agent\work-mode-projects\6abe5daff4b8f86d5cbf9c24"
set "WSL_DIST=Ubuntu-22.04"

echo ==============================================
echo   AI-WAF 一键恢复  (雷池 - 大模型 - 管线)
echo ==============================================
echo.

echo [1/4] 启动雷池 WAF 容器 (WSL) ...
echo       首次启动 WSL 需等待十余秒，请耐心
wsl -d %WSL_DIST% -u root -e bash -c "service docker start >/dev/null 2>&1; cd /data/safeline && docker compose up -d"
echo       完成。
echo.

echo [2/4] 保持 WSL 常驻 (防止空闲自动关机导致反复重启) ...
start "WSL keep-alive" /min "%AIWAF_ROOT%\start_keepalive.bat"
echo       已后台保持，请勿关闭该窗口。
echo.

echo [3/4] 启动 Qwen3-14B 大模型 (新窗口) ...
start "AI-WAF 大模型 CUDA12" "%AIWAF_ROOT%\start_llm.bat"
echo       已在新窗口启动，加载完成后请勿关闭该窗口。
echo.

echo [4/4] 启动闭环管线 (新窗口) ...
start "AI-WAF 管线" "%AIWAF_ROOT%\start_engine.bat"
echo       已在新窗口启动，面板可用后请勿关闭该窗口。
echo.

echo ==============================================
echo   全部启动完成，约 30 秒后可验证：
echo     雷池控制台  https://localhost:9443
echo     大模型      http://127.0.0.1:1234
echo     面板        http://127.0.0.1:8899
echo ==============================================
echo.
echo 提示：若某一项失败，请勿关闭对应窗口的报错退出。
echo.
pause