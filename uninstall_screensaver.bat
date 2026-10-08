@echo off
rem Removes the Threat Monitor screensaver and its saved data.
setlocal
set "KEY=HKCU\Control Panel\Desktop"
rem The setting may hold the long path or its short form (...\THREAT~1\THREAT~1.SCR)
reg query "%KEY%" /v SCRNSAVE.EXE 2>nul | findstr /i "ThreatMonitor THREAT~" >nul
if not errorlevel 1 (
    reg delete "%KEY%" /v SCRNSAVE.EXE /f >nul
    echo Screensaver setting cleared.
)
if exist "%LOCALAPPDATA%\Programs\ThreatMonitor" rmdir /s /q "%LOCALAPPDATA%\Programs\ThreatMonitor"
if exist "%APPDATA%\ThreatMonitor" rmdir /s /q "%APPDATA%\ThreatMonitor"
echo Threat Monitor screensaver removed.
pause
