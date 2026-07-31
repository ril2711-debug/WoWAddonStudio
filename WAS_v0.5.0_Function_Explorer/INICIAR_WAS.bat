@echo off
title WoW Addon Studio v0.4.0
cd /d "%~dp0"
python was\main.py
if errorlevel 1 (
  echo.
  echo Tentando com o comando py...
  py was\main.py
)
echo.
pause
