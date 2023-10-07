# Clang build config
## libjpeg , libpng
```
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" ./configure --disable-shared --prefix={$PREFIX}
```

### to build pngpixel 
```
gclang -c pngpixel.c

gclang -o pngpixel -L../../.libs pngpixel.o -static -lpng16 -lz -lm

get-bc pngpixel

USE_ZLIB=1 test-clang pngpixel.bc -o pngpixel-loop.out
```

## jasper
```
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" cmake -G "Unix Makefiles" -B$YOUR_PATH/build-clang   -DCMAKE_INSTALL_PREFIX={$PREFIX} -DJAS_ENABLE_SHARED=false
```

## openJPEG

```
CC=gclang CXX=gclang++ cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE:string="Release" -DBUILD_SHARED_LIBS:BOOL=OFF -DCMAKE_INSTALL_PREFIX:path="$YOUR_PATH" ..
```
## ffmpeg
### !! Do not use gclang
```
./configure --cc={$ROOT_DIR}/chunk-fuzzer-pass/install/test-clang --cxx={$ROOT_DIR}/chunk-fuzzer-pass/install/test-clang++ --extra-cflags='-O0 -g -fno-discard-value-names -fPIE' --extra-cxxflags='-O0 -g -fno-discard-value-names -fPIE' --prefix={$PREFIX} --disable-runtime-cpudetect --disable-optimizations --disable-mmx --disable-mmxext --disable-sse --disable-sse2 --disable-sse3 --disable-ssse3 --disable-sse4 --disable-sse42 --disable-avx --disable-avx2 --disable-avx512 --disable-stripping --disable-autodetect --disable-doc --disable-pthreads --disable-w32threads --disable-os2threads --disable-network

make -j$(nproc)
```

## libav
### !! Do not use gclang
```
./configure --cc={$ROOT_DIR}/chunk-fuzzer-pass/install/test-clang --extra-cflags='-O0 -g -fno-discard-value-names' --prefix={$PREFIX} --disable-doc --disable-pthreads --disable-w32threads --disable-network --disable-bzlib --disable-gnutls --disable-openssl --disable-zlib --disable-mmx --disable-mmxext --disable-sse --disable-sse2 --disable-sse3 --disable-ssse3 --disable-sse4 --disable-sse42 --disable-avx --disable-avx2 --disable-yasm

make -j$(nproc)
```

## wavpack
```
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" ./configure --disable-asm --enable-man --enable-rpath --enable-tests --disable-dsd --enable-legacy --enable-shared=no --prefix={$PREFIX}
```

## PoDofo
### !! Do not use gclang
### dependency: libfreetype.
First , disable some external library in CmakeLists.txt
|line number|content|
|-----------|-------|
|327 |#FIND_PACKAGE(LIBCRYPTO) 
|337 |#FIND_PACKAGE(LIBIDN) 
|351 |#FIND_PACKAGE(LIBJPEG)
|361 |#FIND_PACKAGE(TIFF)
|371 |#FIND_PACKAGE(PNG)
|382 |#FIND_PACKAGE(UNISTRING)
|396 |#FIND_PACKAGE(CppUnit)
|408 |#FIND_PACKAGE(OpenSSL)
|280 |#SET(WANT_FONTCONFIG TRUE CACHE INTERNAL
|281 |#"True if PoDoFo should be built with fontconfig support")
<br/>
```
mkdir build

cd build 

CC={$ROOT_DIR}/chunk-fuzzer-pass/install/test-clang CXX={$ROOT_DIR}chunk-fuzzer-pass/install/test-clang++ CFLAGS="-O0 -g -fno-discard-value-names -fPIE" CXXFLAGS="-O0 -g -fno-discard-value-names -fPIE" cmake -G "Unix Makefiles" -DWANT_FONTCONFIG:BOOL=FALSE -DPODOFO_BUILD_STATIC:BOOL=TRUE -DPODOFO_BUILD_SHARED:BOOL=FALSE -DPODOFO_NO_MULTITHREAD:BOOL=TRUE \
# -DCMAKE_INCLUDE_PATH={$YOUR_INCLUDE_PATH}/include \
# -DCMAKE_LIBRARY_PATH={$YOUR_LIB_PATH}lib  \
-DCMAKE_INSTALL_PREFIX={$PREFIX}  ..

{$ROOT_DIR}/chunk-fuzzer-pass/tools/gen_library_abilist.sh libfreetype.a discard > podofo_abilist.txt

export ANGORA_TAINT_RULE_LIST={$YOUR_PATH}/podofo_abilist.txt

USE_ZLIB=1 make make -j$(nproc)
```

## libpcap & tcpdump
```
cd libpcap-1.10.0
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" ./configure  --disable-shared --prefix={$YOUR_PATH}
CC=gclang CXX=gclang++ make

cd ../libpcap-1.10.0
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" ./configure --enable-shared=no --prefix=/home/jordan/tests/target-clang-install
CC=gclang CXX=gclang++ make

### runtime parameters
tcpdump --dont-verify-checksums -nr @@

```

## ogg & vorbis
cd ogg
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" ./configure --enable-shared=no --prefix=/home/jordan/tests/target-clang-install
(--disable-crc)
make


cd ../vorbis
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" ./configure --enable-shared=no --prefix=/home/jordan/tests/target-clang-install
make
cd examples
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" make