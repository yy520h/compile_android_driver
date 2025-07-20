#!/bin/bash
export TOOL_PATH=/home/administrator/桌面/r416183b
export PATH=${TOOL_PATH}/bin:$PATH
export TOOL_PATH=/home/administrator/桌面/aarch64-linux-android-4.9
export PATH=${TOOL_PATH}/bin:$PATH
export TOOL_PATH=/home/administrator/桌面/arm-linux-androideabi-4.9
export PATH=${TOOL_PATH}/bin:$PATH

export CLANG_TRIPLE=aarch64-linux-gnu-
export CROSS_COMPILE_COMPAT=arm-linux-gnueabi-
export CROSS_COMPILE=aarch64-linux-gnu-
export CROSS_COMPILE_ARM32=arm-linux-androideabi-

make
