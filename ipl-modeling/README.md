# Input Processing Logic Modeling

## Requirements
- llvm 14.0.6
- rust
- cmake 3.4+

## Build LLVM 14.0.6

> This repo runs stably under llvm 14.0.6, we have not tested other llvm versions.

```
apt-get install -y xz-utils cmake ninja-build gcc g++ python3 doxygen python3-distutils
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/llvm-project-14.0.6.src.tar.xz
tar xf llvm-project-14.0.6.src.tar.xz
mkdir llvm-14.0.6-install
cd llvm-project-14.0.6.src
mkdir build
cd build
CC=gcc CXX=g++ cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -S runtimes -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lldb;compiler-rt" -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" -DCMAKE_INSTALL_PREFIX=path/to/llvm-14.0.6-install ../llvm
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
export LLVM_HOME=path/to/llvm-14.0.6-install
export PATH=$LLVM_HOME/bin:$PATH
export LD_LIBRARY_PATH=$LLVM_HOME/lib:$LLVM_HOME/lib/x86_64-unknown-linux-gnu:$LD_LIBRARY_PATH

./build.sh
```
