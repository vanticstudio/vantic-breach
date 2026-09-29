@echo off
REM ============================================================
REM  Vantic Breach - Windows CLI launcher
REM  Double-click to open the toolkit's interactive menu.
REM
REM  Requires Python 3.8+ from python.org
REM  (installer checkbox: "Add python.exe to PATH").
REM
REM  This script lives at  <project>\app\Windows app\
REM  and runs the CLI from the project root two levels up.
REM ============================================================

setlocal
cd /d "%~dp0..\.."

REM Size the console so the banner, tables and the two-level menu fit
REM (110 cols x 36 rows). Legacy conhost is resized here; Windows
REM Terminal is resized by the app itself (auto_size_terminal).
mode con: cols=110 lines=36
title Vantic Breach

where py >nul 2>nul
if %errorlevel%==0 (
    py vantic.py
    goto end
)

where python >nul 2>nul
if %errorlevel%==0 (
    python vantic.py
    goto end
)

echo.
echo  Python 3.8+ is required.
echo  Install it from https://www.python.org/downloads/
echo  and tick "Add python.exe to PATH" during setup.
echo.

:end
echo.
pause