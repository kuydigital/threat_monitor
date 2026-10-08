@echo off
rem ===========================================================================
rem  Installs the ready-made Threat Monitor screensaver (from the Releases
rem  download). No Python and no admin rights needed.
rem ===========================================================================
setlocal
cd /d "%~dp0"
set "DEST=%LOCALAPPDATA%\Programs\ThreatMonitor"

if not exist "ThreatMonitor\ThreatMonitor.scr" (
    echo This folder doesn't contain the ready-made screensaver.
    echo Download ThreatMonitor-Windows-[version].zip from the project's
    echo Releases page, or run build_screensaver.bat to build it from source.
    goto :fail
)

echo [1/2] Installing to %DEST% ...
robocopy "ThreatMonitor" "%DEST%" /MIR /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 goto :fail

echo [2/2] Setting Threat Monitor as your screensaver...
call "%~dp0register_screensaver.bat"
if errorlevel 1 goto :fail

echo.
echo Done. You can delete this downloaded folder now.
echo.
pause
exit /b 0

:fail
echo.
echo Installation failed - see the message above.
pause
exit /b 1
