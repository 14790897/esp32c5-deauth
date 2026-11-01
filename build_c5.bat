@echo off
setlocal

rem Build the ESP32-C5 firmware. Requires an ESP-IDF v6.1 installation.
rem Set IDF_PATH (or run this from an ESP-IDF terminal) before invoking.

set "MSYSTEM="
set "SHELL="

if "%IDF_PATH%"=="" (
    echo [ERROR] IDF_PATH is not set. Point it at your ESP-IDF v6.1 installation.
    exit /b 1
)

call "%IDF_PATH%\export.bat"
if errorlevel 1 exit /b 1

rem The RISC-V assembler in the Windows toolchain is a launcher that needs
rem its sibling *-as-xespv2p1/p2.exe files; GCC looks up a plain "as".
rem tools\make_toolchain_shim.py creates this directory.
set "PATH=%~dp0toolchain_shim;%PATH%"

cd /d "%~dp0"

if not exist sdkconfig (
    idf.py set-target esp32c5
    if errorlevel 1 exit /b 1
)

idf.py build
