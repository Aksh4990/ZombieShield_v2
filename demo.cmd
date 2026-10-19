@echo off
REM One click: sets up and starts the ZombieShield demo (Docker Desktop required). See docs\DEMO.md.
cd /d "%~dp0"
echo.
echo ZombieShield demo
echo.
choice /C YN /T 15 /D Y /M "Start from a clean slate? This wipes ZombieShield data from earlier runs (Y, default in 15 s) or keeps it (N)"
if errorlevel 2 (set FRESH=) else (set FRESH=-Fresh)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\demo.ps1" %FRESH%
echo.
pause
