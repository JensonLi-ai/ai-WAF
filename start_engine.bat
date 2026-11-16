@echo off
chcp 936 >nul
title AI-WAF Engine
cd /d "C:\Users\Administrator\AppData\Roaming\Trae CN\ModularData\ai-agent\work-mode-projects\6abe5daff4b8f86d5cbf9c24"

rem fetch WSL IP dynamically (it changes after reboot; localhost forwarding to WSL may fail)
for /f "tokens=1" %%i in ('wsl -d Ubuntu-22.04 -u root hostname -I') do set "WSL_IP=%%i"
set "SAFELINE_BASE=https://%WSL_IP%:9443"

echo [AI-WAF] engine starting, panel http://127.0.0.1:8899
echo          safeline=%SAFELINE_BASE%
echo          (close this window to stop the service)
python -m aiwaf.main
pause