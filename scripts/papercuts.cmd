@echo off
REM Wrapper so agents can call: scripts\papercuts.cmd add "text"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0papercuts.ps1" %*
