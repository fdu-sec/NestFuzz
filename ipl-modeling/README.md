# chunk-fuzzer-pass

## DEPENDENCIES
- llvm 10.0.0+
- rust
- cmake 3.4+
- go 
- gclang

## COMPILE & INSTALL
```
./build.sh
```

## USAGE

# libjpeg for example
```
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" ./configure  --disable-shared
make
get-bc djpeg
$ABSOLUTE_PATH/chunk-fuzzer-pass/install/test-clang djpeg.bc -o djpeg-loop.out
```