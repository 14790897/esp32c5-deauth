@echo off
setlocal

if "%~1"=="" (
    echo Usage: flash_c5.bat COMx
    exit /b 1
)

set "MSYSTEM="
set "SHELL="

if "%IDF_PATH%"=="" (
    echo [ERROR] IDF_PATH is not set. Point it at your ESP-IDF v6.1 installation.
    exit /b 1
)

call "%IDF_PATH%\export.bat"
if errorlevel 1 exit /b 1

set "PATH=%~dp0toolchain_shim;%PATH%"
cd /d "%~dp0"

idf.py -p %~1 flash
