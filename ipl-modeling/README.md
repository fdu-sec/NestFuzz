# Input Processing Logic Modeling

## Requirements
- llvm 10.0.0+
- rust
- cmake 3.4+
- go 
- gclang

## Build LLVM 10.0.0
```
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
export LLVM_HOME=/path/to/llvm-10.0.0-install
export PATH=$LLVM_HOME/bin:$PATH
export LD_LIBRARY_PATH=$LLVM_HOME/lib:$LD_LIBRARY_PATH
./build.sh
```