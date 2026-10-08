@echo off
rem ===========================================================================
rem  Makes Threat Monitor your Windows screensaver and opens Screen Saver
rem  Settings. Run it after build_screensaver.bat (which also calls it).
rem  No admin rights needed - please run it by double-clicking.
rem ===========================================================================
setlocal
set "SCR=%LOCALAPPDATA%\Programs\ThreatMonitor\ThreatMonitor.scr"
set "KEY=HKCU\Control Panel\Desktop"

if not exist "%SCR%" (
    echo ThreatMonitor.scr was not found in %LOCALAPPDATA%\Programs\ThreatMonitor
    echo Run build_screensaver.bat first.
    goto :fail
)

rem Windows prefers the short form of the path, which never contains spaces.
for %%I in ("%SCR%") do set "SCR_SHORT=%%~sI"

reg add "%KEY%" /v SCRNSAVE.EXE /t REG_SZ /d "%SCR_SHORT%" /f >nul
if errorlevel 1 goto :fail
reg add "%KEY%" /v ScreenSaveActive /t REG_SZ /d 1 /f >nul
if errorlevel 1 goto :fail
reg query "%KEY%" /v ScreenSaveTimeOut >nul 2>&1
if errorlevel 1 reg add "%KEY%" /v ScreenSaveTimeOut /t REG_SZ /d 600 /f >nul

net session >nul 2>&1
if not errorlevel 1 (
    echo Note: this window is running as administrator, which is not needed.
    echo If ThreatMonitor is not selected in Screen Saver Settings, close this,
    echo then double-click register_screensaver.bat normally.
    echo.
)

echo Threat Monitor is now your screensaver:
echo     %SCR%
echo.
echo Opening Screen Saver Settings. ThreatMonitor should be selected -
echo choose the wait time and click OK. If it is not shown, click Cancel
echo instead: the screensaver is already set and will still start.
echo To try it now:
echo     "%SCR%" /s
control.exe desk.cpl,,@screensaver
exit /b 0

:fail
echo.
echo Could not set the screensaver - see the message above.
pause
exit /b 1
