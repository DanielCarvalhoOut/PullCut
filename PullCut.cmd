@echo off
rem Inicia o PullCut e abre no navegador. Feche a janela "PullCut - servidor" para parar.
cd /d "%~dp0"
start "PullCut - servidor" /min node server.mjs
timeout /t 2 /nobreak >nul
start "" http://127.0.0.1:4747
