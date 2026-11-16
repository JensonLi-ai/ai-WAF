@echo off
title WSL keep-alive
chcp 936 >nul
echo WSL keep-alive started. Keep this window open to prevent WSL idle shutdown.
:loop
wsl -d Ubuntu-22.04 -u root -e bash -c "sleep infinity"
timeout /t 5 /nobreak >nul
goto loop