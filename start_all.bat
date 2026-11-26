@echo off
chcp 936 >nul
title AI-WAF 一键启动
setlocal EnableExtensions

set "AIWAF_ROOT=C:\Users\Administrator\AppData\Roaming\Trae CN\ModularData\ai-agent\work-mode-projects\6abe5daff4b8f86d5cbf9c24"
set "AIWAF_LX=/mnt/c/Users/Administrator/AppData/Roaming/Trae CN/ModularData/ai-agent/work-mode-projects/6abe5daff4b8f86d5cbf9c24"
set "WSL_DIST=Ubuntu-22.04"
set "LLM_DIR=H:\AIWAF\backend\extensions\backends\llama.cpp-win-x86_64-nvidia-cuda12-avx2-2.30.0"
set "LLM_MODEL=H:\AIWAF\lmstudio\models\Qwen\qwen3-14b-abliterated\qwen3-14b-abliterated-Q4_K_M.gguf"
set "PWD_FILE=%USERPROFILE%\.aiwaf\safeline.pwd"

cd /d "%AIWAF_ROOT%"

echo ==============================================
echo   AI-WAF 一键启动
echo   WSL - 雷池 - 采集器 - 大模型 - 闭环引擎
echo ==============================================
echo.

echo [1/7] 检查 WSL ...
wsl -d %WSL_DIST% -u root -e /bin/true
if errorlevel 1 (
    echo   [错误] 无法启动 WSL 发行版 %WSL_DIST%
    goto :failed
)

echo [2/7] 启动 Docker 与雷池容器 ...
wsl -d %WSL_DIST% -u root -e bash -c "service docker start >/dev/null 2>&1; cd /data/safeline && docker compose up -d"
if errorlevel 1 (
    echo   [错误] 雷池容器启动失败
    goto :failed
)

echo [3/7] 等待雷池控制台就绪 ...
for /f "tokens=1" %%i in ('wsl -d %WSL_DIST% -u root hostname -I') do set "WSL_IP=%%i"
if not defined WSL_IP (
    echo   [错误] 获取 WSL IP 失败
    goto :failed
)
set "SAFELINE_BASE=https://%WSL_IP%:9443"
call :wait_url "%SAFELINE_BASE%/" 120
if errorlevel 1 (
    echo   [错误] 雷池控制台未就绪：%SAFELINE_BASE%
    goto :failed
)
echo   雷池地址 %SAFELINE_BASE%

echo [4/7] 启动旁路采集器 ...
wsl -d %WSL_DIST% -u root sh "%AIWAF_LX%/deploy/run_collector.sh"
if errorlevel 1 (
    echo   [错误] 采集器启动失败
    goto :failed
)

echo [5/7] 启动本地大模型 ...
curl.exe -sf -m 3 -o NUL http://127.0.0.1:1234/v1/models >nul 2>&1
if errorlevel 1 (
    if not exist "%LLM_DIR%\llama-server.exe" (
        echo   [错误] 未找到 llama-server.exe：%LLM_DIR%
        goto :failed
    )
    start "" /D "%LLM_DIR%" "%LLM_DIR%\llama-server.exe" --model "%LLM_MODEL%" --host 127.0.0.1 --port 1234 -c 16384 -ngl 999
    echo   模型加载中（约 30-90 秒）...
) else (
    echo   模型已在运行，跳过启动
)
call :wait_url "http://127.0.0.1:1234/v1/models" 300
if errorlevel 1 (
    echo   [错误] 模型未就绪，请查看 "AI-WAF 大模型" 窗口
    goto :failed
)
echo   模型就绪 http://127.0.0.1:1234

echo [6/7] 检查雷池登录凭证 ...
if not exist "%PWD_FILE%" (
    echo   [错误] 缺少 %PWD_FILE%
    echo   请把雷池控制台 admin 密码写入该文件后重试。
    goto :failed
)

echo [7/7] 启动闭环引擎与面板 ...
set "SAFELINE_AUTH_MODE=jwt"
set "PYTHONIOENCODING=gbk"
set "AIWAF_WSL_IP=%WSL_IP%"
set "RUN_MODE=auto"
set "WEB_PORT=8899"
set "MISS_COLLECTOR_PORT=18088"
echo.
echo ==============================================
echo   面板  http://127.0.0.1:8899
echo   雷池  %SAFELINE_BASE%
echo   模型  http://127.0.0.1:1234
echo   关闭本窗口只停止引擎，其它组件继续运行
echo ==============================================
echo.
python -m aiwaf.boot
echo.
echo 引擎已退出。
pause
exit /b 0

:wait_url
set "URL=%~1"
set /a LEFT=%~2
:wait_loop
curl.exe -sfk -m 5 -o NUL "%URL%" >nul 2>&1
if not errorlevel 1 exit /b 0
set /a LEFT-=1
if %LEFT% leq 0 exit /b 1
timeout /t 3 /nobreak >nul
goto :wait_loop

:failed
echo.
echo 启动中断，请把上面的报错发给维护者。
pause
exit /b 1
