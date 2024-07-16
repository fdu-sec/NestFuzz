// clang -O0 -emit-llvm simple_loop_test.c -c -o simple_loop_test.bc
// llvm-dis simple_loop_test.bc -o -
// 


// clang -fpass-plugin=/NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so -loop-handling-pass -mllvm -chunk-exploitation-list=/NestFuzz_t/ipl-modeling/install/rules/angora_abilist.txt simple_loop_test.bc

// clang -O0 -emit-llvm simple_loop_test.c -c -o simple_loop_test.bc

// opt -load /NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so -load-pass-plugin /NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so -passes=loop-handling-pass -chunk-exploitation-list=/NestFuzz_t/ipl-modeling/install/rules/angora_abilist.txt simple_loop_test.bc


// clang -fpass-plugin=/NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so simple_loop_test.bc
// opt-10 -load /nestfuzz/ipl-modeling/install/pass/libLoopHandlingPass.so -load-pass-plugin /nestfuzz/ipl-modeling/install/pass/libLoopHandlingPass.so -loop-handling-pass -chunk-exploitation-list=/nestfuzz/ipl-modeling/install/rules/angora_abilist.txt simple_loop_test.bc
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char a[10] = "abcdefghi";
    char b;
    for (int i = 0; i < 9; ++i) {
        b = a[i];
        printf("%c\n", b);
    }
    return 0;
}


// 完全正确
// clang -O0 -emit-llvm simple_loop_test.c -c -o simple_loop_test.bc \
-Xclang -load -Xclang /NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so \
-Xclang -fpass-plugin=/NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so \
-mllvm -chunk-exploitation-list=/NestFuzz_t/ipl-modeling/install/rules/angora_abilist.txt

//clang -o loopTest loopTest.c \
-Xclang -load -Xclang /NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so \
-Xclang -fpass-plugin=/NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so \
-mllvm -chunk-exploitation-list=/NestFuzz_t/ipl-modeling/install/rules/exploitation_list.txt \
-pie -fpic -Qunused-arguments -fno-discard-value-names -g -O0 \
-Wl,--whole-archive /NestFuzz_t/ipl-modeling/install/lib/libdfsan_rt-x86_64.a \
-Wl,--no-whole-archive -Wl,--dynamic-list=/NestFuzz_t/ipl-modeling/install/lib/libdfsan_rt-x86_64.a.syms \
/NestFuzz_t/ipl-modeling/install/lib/libruntime.so /NestFuzz_t/ipl-modeling/install/lib/libDFSanIO.a \
-lstdc++ -lrt -Wl,--no-as-needed -Wl,--gc-sections -ldl -lpthread -lm

//gdb --args clang -o loopTest loopTest.c \
-Xclang -load -Xclang /nestfuzz/ipl-modeling/install/pass/libDFSanPass.so \
-Xclang -fpass-plugin=/nestfuzz/ipl-modeling/install/pass/libDFSanPass.so \
-mllvm -chunk-dfsan-abilist=/nestfuzz/ipl-modeling/install/rules/angora_abilist.txt \
-mllvm -chunk-dfsan-abilist=/nestfuzz/ipl-modeling/install/rules/dfsan_abilist.txt \
-pie -fpic -Qunused-arguments -fno-discard-value-names -g -O0 \
-Wl,--whole-archive /nestfuzz/ipl-modeling/install/lib/libdfsan_rt-x86_64.a \
-Wl,--no-whole-archive -Wl,--dynamic-list=/nestfuzz/ipl-modeling/install/lib/libdfsan_rt-x86_64.a.syms \
/nestfuzz/ipl-modeling/install/lib/libruntime.so /nestfuzz/ipl-modeling/install/lib/libDFSanIO.a \
-lstdc++ -lrt -Wl,--no-as-needed -Wl,--gc-sections -ldl -lpthread -lm