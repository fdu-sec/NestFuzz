// clang -O0 -emit-llvm simple_loop_test.c -c -o simple_loop_test.bc
// llvm-dis simple_loop_test.bc -o -
// opt -load-pass-plugin ./libLoopHandlingPass.so -passes=loop-handling-pass ../test/simple_loop_test.bc

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