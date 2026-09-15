@echo off
setlocal
cd /d "%~dp0"

if not defined PORT set "PORT=3000"
if not defined SERVER_LOG set "SERVER_LOG=server_run.log"

set "URL=http://localhost:%PORT%"

echo ==============================================
echo   Announce - Development Server Launcher
echo ==============================================
echo.

where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js was not found in PATH.
    echo Install Node.js from https://nodejs.org and try again.
    echo.
    pause
    exit /b 1
)

netstat -ano | findstr ":%PORT%" | findstr "LISTENING" >nul 2>nul
if not errorlevel 1 (
    echo [INFO] A server is already running on port %PORT%.
    echo        Open %URL% in your browser, or stop that server first.
    echo.
    pause
    exit /b 0
)

echo Starting server detached on port %PORT% ...
echo.

start "Announce Server" /min cmd /c "node server.js >> %SERVER_LOG% 2>&1"

echo Server started in the background.
echo.
echo   URL : %URL%
echo   Log : %CD%\%SERVER_LOG%
echo.
echo Close the minimized "Announce Server" window to stop it.
echo.
pause
endlocal