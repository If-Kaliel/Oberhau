@echo off
setlocal
chcp 65001 >nul
title OBERHAU - Desktop
cd /d "%~dp0"

if not exist "src\oberhau\__main__.py" (
  echo [ERRO] Este inicializador precisa estar na pasta raiz do Oberhau.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo [ERRO] Ambiente Python nao encontrado.
  echo No PowerShell desta pasta execute:
  echo powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Setup.ps1
  pause
  exit /b 1
)

set "PYTHONPATH=%CD%\src"
set "PATH=%CD%\.venv\Scripts;%PATH%"
echo Abrindo a interface Oberhau...
echo Se ocorrer erro, ele aparecera aqui.
echo.
".venv\Scripts\python.exe" -m oberhau gui
if errorlevel 1 (
  echo.
  echo [ERRO] O Oberhau terminou com erro. Copie a mensagem acima.
  pause
)
