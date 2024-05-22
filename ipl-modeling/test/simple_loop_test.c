// clang -O0 -emit-llvm simple_loop_test.c -c -o simple_loop_test.bc
// llvm-dis simple_loop_test.bc -o -
// opt -load /NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so -load-pass-plugin /NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so -passes=loop-handling-pass -chunk-dfsan-abilist=/NestFuzz_t/ipl-modeling/install/rules/angora_abilist.txt simple_loop_test.bc
// clang -fpass-plugin=/NestFuzz_t/ipl-modeling/install/pass/libLoopHandlingPass.so simple_loop_test.bc
// opt-10 -load /nestfuzz/ipl-modeling/install/pass/libLoopHandlingPass.so -load-pass-plugin /nestfuzz/ipl-modeling/install/pass/libLoopHandlingPass.so -passes=loop-handling-pass -chunk-dfsan-abilist=/nestfuzz/ipl-modeling/install/rules/angora_abilist.txt simple_loop_test.bc
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