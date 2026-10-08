@echo off
rem ===========================================================================
rem  Builds the Threat Monitor screensaver from source and installs it.
rem  (Most people don't need this: install.bat in the ready-made download
rem  from the Releases page needs no Python at all.)
rem
rem  Needs Python 3.9+. If it isn't installed, this offers to install
rem  Python 3.13 for you (just for your user account, no admin needed).
rem  Run it by double-clicking, not with "Run as administrator".
rem ===========================================================================
setlocal
cd /d "%~dp0"
set "DEST=%LOCALAPPDATA%\Programs\ThreatMonitor"
set "VENV=%~dp0.build-env"
set "VPY=%VENV%\Scripts\python.exe"

echo [1/6] Looking for Python...
call :find_python
if not defined PY call :install_python
if not defined PY goto :fail
echo       Using %PY%

echo [2/6] Preparing a private build environment...
if not exist "%VPY%" (
    call %PY% -m venv "%VENV%"
    if errorlevel 1 goto :fail
)

echo [3/6] Installing build tools (pygame-ce, requests, pyinstaller)...
rem --only-binary: use ready-made packages only, never try to compile anything
"%VPY%" -m pip install --disable-pip-version-check --quiet --upgrade --only-binary=:all: pygame-ce requests "pyinstaller>=6,<7"
if errorlevel 1 (
    echo.
    echo Could not download ready-made packages for this Python version.
    echo Install Python 3.13 from python.org, delete the .build-env folder, and run this again.
    goto :fail
)

echo [4/6] Building the screensaver (takes a minute)...
"%VPY%" -m PyInstaller --noconfirm --clean --log-level WARN --windowed --name ThreatMonitor threat_screensaver.py
if errorlevel 1 goto :fail

echo [5/6] Installing to %DEST% ...
robocopy "dist\ThreatMonitor" "%DEST%" /MIR /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 goto :fail
move /y "%DEST%\ThreatMonitor.exe" "%DEST%\ThreatMonitor.scr" >nul
if errorlevel 1 goto :fail

echo [6/6] Setting Threat Monitor as your screensaver...
call "%~dp0register_screensaver.bat"
if errorlevel 1 goto :fail

echo.
echo Done. The .build-env, build and dist folders here can be deleted afterwards.
echo.
pause
exit /b 0

:fail
echo.
echo Build failed - see the messages above.
pause
exit /b 1


rem ---------------------------------------------------------------------------
rem  Find a working Python 3.9+. Each candidate is actually run and must print
rem  "ok", because on Windows 11 "python" can be a shortcut that only opens
rem  the Microsoft Store. Checking the printed text (not the exit code) also
rem  works for .bat shims such as pyenv-win.
rem ---------------------------------------------------------------------------
:find_python
set "PY="
call :try_python py -3
if not defined PY call :try_python python
if not defined PY for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if not defined PY call :try_python "%%~fD\python.exe"
)
exit /b 0

:try_python
set "PY_OUT="
for /f "delims=" %%V in ('call %* -c "import sys; print('ok' if sys.version_info[:2] >= (3, 9) else 'old')" 2^>nul') do set "PY_OUT=%%V"
if "%PY_OUT%"=="ok" set "PY=%*"
exit /b 0


rem ---------------------------------------------------------------------------
rem  Offer to install Python 3.13 with winget (built into Windows 10/11).
rem ---------------------------------------------------------------------------
:install_python
echo.
echo Python is needed to build the screensaver, and it isn't installed.
echo (Only for building - the finished screensaver carries its own copy.)
echo.
winget --version >nul 2>&1
if errorlevel 1 goto :no_winget
choice /c YN /m "Install Python 3.13 now (about 30 MB, just for your account, no admin)"
if errorlevel 2 goto :manual_python
echo Installing Python 3.13 - this takes a minute or two...
winget install --id Python.Python.3.13 --exact --scope user --silent --accept-package-agreements --accept-source-agreements --override "/quiet InstallAllUsers=0 Include_launcher=0 InstallLauncherAllUsers=0 Include_test=0 Shortcuts=0 PrependPath=0"
call :find_python
if defined PY exit /b 0
echo.
echo Python was installed but could not be found yet.
echo Close this window and double-click build_screensaver.bat again.
exit /b 0

:no_winget
echo winget, the Windows package installer, isn't available on this PC.
:manual_python
echo Opening the Python download page. Install Python 3.13, tick
echo "Add python.exe to PATH" on the first screen, then run this again.
start "" "https://www.python.org/downloads/windows/"
exit /b 0
