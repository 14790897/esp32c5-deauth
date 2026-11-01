cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Seed the RISC-V flags before project() so the CMake compiler check links
# against the rv32imac multilib instead of the toolchain's rv32imafdc default.
set(CMAKE_C_FLAGS "-march=rv32imac_zicsr_zifencei_zaamo_zalrsc -mabi=ilp32")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_C_FLAGS}")

project(c5_deauth)
