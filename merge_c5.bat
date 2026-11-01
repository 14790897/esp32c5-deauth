@echo off
setlocal

rem Merge bootloader + partition table + application into one 4 MB image
rem that can be flashed at offset 0x0.
rem Run build_c5.bat first.

set "MSYSTEM="
set "SHELL="

if "%IDF_PATH%"=="" (
    echo [ERROR] IDF_PATH is not set. Point it at your ESP-IDF v6.1 installation.
    exit /b 1
)

call "%IDF_PATH%\export.bat"
if errorlevel 1 exit /b 1

cd /d "%~dp0"

python -m esptool --chip esp32c5 merge-bin -o build\c5_deauth_full.bin --target-offset 0 --flash-mode dio --flash-freq 80m --flash-size 4MB --pad-to-size 4MB 0x2000 build\bootloader\bootloader.bin 0x8000 build\partition_table\partition-table.bin 0x10000 build\c5_deauth.bin
