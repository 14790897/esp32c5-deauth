@echo off
set "MSYSTEM="
set "SHELL="
call "C:\Espressif\frameworks\esp-idf-v5.5.2\export.bat"
set "PATH=C:\git-program\claude-hardware\c5-deauth\toolchain_shim;%PATH%"
cd /d C:\git-program\claude-hardware\c5-deauth
idf.py -p COM12 monitor
