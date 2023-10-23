# Input Processing Logic Modeling

## Requirements
- llvm 10.0.0+
- rust
- cmake 3.4+

## Build LLVM 10.0.0

> This repo runs stably under llvm 10.0.0, we have not tested other llvm versions.

```
apt-get install -y xz-utils cmake ninja-build gcc g++ python3 doxygen python3-distutils
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/llvm-project-10.0.0.tar.xz
tar xf llvm-project-10.0.0.tar.xz
mkdir llvm-10.0.0-install
cd llvm-project-10.0.0
mkdir build
CC=gcc CXX=g++ cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;libcxx;libcxxabi;lldb;compiler-rt" -DCMAKE_INSTALL_PREFIX=/path/to/llvm-10.0.0-install -DCMAKE_EXE_LINKER_FLAGS="-lstdc++" ../llvm
ninja install
```

## Compile
```
# install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# other dependencies
apt install git zlib1g-dev python-is-python3 -y

# llvm
export LLVM_HOME=/path/to/llvm-10.0.0-install
export PATH=$LLVM_HOME/bin:$PATH
export LD_LIBRARY_PATH=$LLVM_HOME/lib:$LD_LIBRARY_PATH

./build.sh
```
