@echo off
rem ---------------------------------------------------------------------------
rem  Halyard launcher for Windows.
rem
rem  Double-click this, or run it from a prompt. It starts the server in this
rem  window and opens the tokened URL in your default browser once the port is
rem  actually accepting connections.
rem
rem  Why a launcher rather than just opening public\index.html: that page reads
rem  its token from the query string and calls root-relative /api/... endpoints,
rem  so as a file:// page it paints but connects to nothing. The URL this script
rem  opens is the only one that works.
rem
rem  Close this window, or press Ctrl+C, to stop Halyard.
rem ---------------------------------------------------------------------------
setlocal EnableExtensions

if /i "%~1"=="--open-when-up" goto :open_when_up

cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
  echo.
  echo   Node is not on PATH. Halyard needs Node 18.17 or newer:
  echo   https://nodejs.org
  echo.
  pause
  exit /b 1
)

rem The URL - token included - comes from Halyard itself rather than being
rem rebuilt here, so a changed port, a rotated token or a configured publicUrl
rem is picked up with no edit to this file.
set "HALYARD_URL="
for /f "usebackq delims=" %%U in (`node "bin\halyard.js" token --url 2^>nul`) do set "HALYARD_URL=%%U"

if not defined HALYARD_URL (
  echo.
  echo   No token yet - running first-time setup.
  echo.
  node "bin\halyard.js" setup
  if errorlevel 1 (
    echo.
    echo   Setup failed. Run "node bin\halyard.js doctor" to see why.
    echo.
    pause
    exit /b 1
  )
  for /f "usebackq delims=" %%U in (`node "bin\halyard.js" token --url 2^>nul`) do set "HALYARD_URL=%%U"
)

if not defined HALYARD_URL (
  echo.
  echo   Could not work out the Halyard URL.
  echo   Run "node bin\halyard.js doctor" to see what is missing.
  echo.
  pause
  exit /b 1
)

rem Pull the port back out of that URL, so "already running" can be told from
rem "not running yet". A publicUrl with no explicit port leaves the port empty,
rem which the opener below treats as "wait a moment, then open it anyway".
set "_rest=%HALYARD_URL:*//=%"
set "_portish="
set "HALYARD_PORT="
for /f "tokens=2 delims=:" %%P in ("%_rest%") do set "_portish=%%P"
if defined _portish for /f "tokens=1 delims=/" %%P in ("%_portish%") do set "HALYARD_PORT=%%P"

if defined HALYARD_PORT (
  netstat -an | findstr /c:":%HALYARD_PORT% " | findstr /i /c:"LISTENING" >nul
  if not errorlevel 1 (
    echo.
    echo   Halyard is already listening on port %HALYARD_PORT% - opening the browser.
    echo   Leave whichever window is running it open; this one has nothing to do.
    echo.
    start "" "%HALYARD_URL%"
    exit /b 0
  )
)

rem Open the browser from a second copy of this script so the server can own
rem this window: log lines stay visible and Ctrl+C still stops it.
start "Halyard browser" /b cmd /c call "%~f0" --open-when-up "%HALYARD_URL%" "%HALYARD_PORT%"

node "bin\halyard.js" start
set "_rc=%errorlevel%"
if not "%_rc%"=="0" (
  echo.
  echo   Halyard exited with code %_rc%.
  echo.
  pause
)
exit /b %_rc%


rem ---------------------------------------------------------------------------
rem  Second entry point: wait for the port, then open the browser. Polling the
rem  port beats sleeping a fixed guess - the difference between a tab that loads
rem  and a tab showing a connection error on a slow first start.
rem ---------------------------------------------------------------------------
:open_when_up
set "_url=%~2"
set "_port=%~3"

if not defined _port (
  ping -n 4 127.0.0.1 >nul
  start "" "%_url%"
  exit /b 0
)

rem ping -n 2 is a one-second wait; 60 passes is roughly a minute of patience.
for /l %%i in (1,1,60) do (
  netstat -an | findstr /c:":%_port% " | findstr /i /c:"LISTENING" >nul
  if not errorlevel 1 goto :open_now
  ping -n 2 127.0.0.1 >nul
)

echo.
echo   Halyard did not start listening on port %_port% within a minute.
echo   The server log above should say why; nothing was opened.
echo.
exit /b 1

:open_now
start "" "%_url%"
exit /b 0
