@echo off
REM Stops the ZombieShield demo containers. Data is kept; demo.cmd starts them again.
cd /d "%~dp0"
docker compose --profile sockshop stop
echo.
echo Stopped. Run demo.cmd to start again.
pause
