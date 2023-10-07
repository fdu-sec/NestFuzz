#!/usr/bin/env bash

BIN_PATH=$(readlink -f "$0")
ROOT_DIR=$(dirname $(dirname $(dirname $BIN_PATH)))

LLVM_VERSION=10.0.0

NINJA_B=`which ninja 2>/dev/null`

if [ "$NINJA_B" = "" ]; then
    echo "[-] Error: can't find 'ninja' in your \$PATH. please install ninja-build" 1>&2
    echo "[-] Debian&Ubuntu: sudo apt-get install ninja-build" 1>&2
    exit 1
fi

set -euxo pipefail

CUR_DIR=`pwd`
CLANG_SRC=${CUR_DIR}/llvm_src

# if [ ! -d $CLANG_SRC ]; then
# wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/llvm-${LLVM_VERSION}.src.tar.xz
# # wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/cfe-${LLVM_VERSION}.src.tar.xz
# wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/compiler-rt-${LLVM_VERSION}.src.tar.xz
# wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/libcxx-${LLVM_VERSION}.src.tar.xz
# wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/libcxxabi-${LLVM_VERSION}.src.tar.xz
# wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/libunwind-${LLVM_VERSION}.src.tar.xz
# wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang-tools-extra-${LLVM_VERSION}.src.tar.xz


rm -rf $CLANG_SRC

tar -Jxf ${CUR_DIR}/llvm-${LLVM_VERSION}.src.tar.xz 
mv llvm-${LLVM_VERSION}.src $CLANG_SRC

cd ${CLANG_SRC}/tools
# tar -Jxf ${CUR_DIR}/cfe-${LLVM_VERSION}.src.tar.xz 
# mv cfe-${LLVM_VERSION}.src clang
cd ${CLANG_SRC}/tools/clang/tools
tar -Jxf ${CUR_DIR}/clang-tools-extra-${LLVM_VERSION}.src.tar.xz 
mv clang-tools-extra-${LLVM_VERSION}.src extra
cd ${CLANG_SRC}/projects
tar -Jxvf ${CUR_DIR}/compiler-rt-${LLVM_VERSION}.src.tar.xz
mv compiler-rt-${LLVM_VERSION}.src compiler-rt
tar -Jxvf ${CUR_DIR}/libcxx-${LLVM_VERSION}.src.tar.xz
mv libcxx-${LLVM_VERSION}.src libcxx
tar -Jxvf ${CUR_DIR}/libcxxabi-${LLVM_VERSION}.src.tar.xz
mv libcxxabi-${LLVM_VERSION}.src libcxxabi
tar -Jxvf ${CUR_DIR}/libunwind-${LLVM_VERSION}.src.tar.xz
mv libunwind-${LLVM_VERSION}.src libunwind
cp ./libcxxabi/include/*  ./libcxx/include

rm -rf ${CUR_DIR}/*.tar.xz
fi

cd $CUR_DIR

rm -rf build_*

mkdir build_fast && cd build_fast/
CC=clang CXX=clang++ cmake -G Ninja ../llvm_src  -DLIBCXXABI_ENABLE_SHARED=NO -DLIBCXX_ENABLE_SHARED=NO -DLIBCXX_CXX_ABI=libcxxabi 
#-DLLVM_FORCE_USE_OLD_TOOLCHAIN=YES 
ninja cxx cxxabi

cd ..
mkdir build_track && cd build_track/

sudo apt install libc++-10-dev libc++abi-10-dev
USE_FAST=1 CC=${ROOT_DIR}/install/test-clang CXX=${ROOT_DIR}/install/test-clang++ cmake -G Ninja ../llvm_src  -DLIBCXXABI_ENABLE_SHARED=NO -DLIBCXX_ENABLE_SHARED=NO -DLIBCXX_CXX_ABI=libcxxabi 
#-DLLVM_FORCE_USE_OLD_TOOLCHAIN=YES 
USE_DFSAN=1 ninja cxx cxxabi

# @echo "if cxxabi.h not found, try: cp ./libcxxabi/include/*  ./libcxx/include, or -I"

# @echo "if libstdc++ version must be at least 5.1, try: sudo apt install libc++-10-dev libc++abi-10-dev"


@echo "Please install them again to overwrite old ones (by CMake).
