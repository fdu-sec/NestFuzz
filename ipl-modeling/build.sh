#!/bin/bash

BIN_PATH=$(readlink -f "$0")
ROOT_DIR=$(dirname $BIN_PATH)

set -euxo pipefail

if [ -x "$(command -v llvm-config-10)"  ]; then
    echo "Find llvm-config-10"
elif [ -x "$(command -v llvm-config)" ]; then
    echo "Find llvm-config"
else
    exit 1
fi

PREFIX=${PREFIX:-${ROOT_DIR}/install/}

[ -z ${DEBUG+x} ]&&DEBUG=0

if [ $DEBUG -eq 0 ]; then
    cargo build --release
else
    cargo build
fi

rm -rf ${PREFIX}
mkdir -p ${PREFIX}
mkdir -p ${PREFIX}/lib

if [ $DEBUG -eq 0 ]; then
    cp target/release/*.so ${PREFIX}/lib
    # cp target/release/*.a ${PREFIX}/lib
else
    cp target/debug/*.so ${PREFIX}/lib
    # cp target/debug/*.a ${PREFIX}/lib
fi

rm -rf build
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=${PREFIX} -DCMAKE_BUILD_TYPE=Release ..
make # VERBOSE=1 
make install # VERBOSE=1
