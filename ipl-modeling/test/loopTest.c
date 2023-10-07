// clang -O0 -emit-llvm loopTest.c -c -o loopTest.bc
// llvm-dis loopTest.bc -o -
// opt -load-pass-plugin ./libLoopHandlingPass.so -passes=loop-handling-pass ../test/loopTest.ll

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../dfsan_rt/dfsan_interface.h"


/*
test-clang loopTest.c -o loopTest

./loopTest 2>&1                             
0123456789fp_label: 0
[]
buffer_label: 4
[TagSeg { sign: false, begin: 0, end: 1 }, TagSeg { sign: false, begin: 1, end: 2 }]
dst_label: 4
[TagSeg { sign: false, begin: 0, end: 1 }, TagSeg { sign: false, begin: 1, end: 2 }]
34 
buffer_label: 9
[TagSeg { sign: false, begin: 2, end: 3 }, TagSeg { sign: false, begin: 3, end: 4 }]
dst_label: 9
[TagSeg { sign: false, begin: 2, end: 3 }, TagSeg { sign: false, begin: 3, end: 4 }]
buffer_label: 14
[TagSeg { sign: false, begin: 4, end: 5 }, TagSeg { sign: false, begin: 5, end: 6 }]
dst_label: 14
[TagSeg { sign: false, begin: 4, end: 5 }, TagSeg { sign: false, begin: 5, end: 6 }]
buffer_label: 19
[TagSeg { sign: false, begin: 6, end: 7 }, TagSeg { sign: false, begin: 7, end: 8 }]
dst_label: 19
[TagSeg { sign: false, begin: 6, end: 7 }, TagSeg { sign: false, begin: 7, end: 8 }]

*/


void foo() {
    for(int i = 0; i < 10; ++i)
        printf("%d",i);
	printf("\n");
}

int main()
{
	foo();
	FILE *fp;
	fp = fopen("file", "rb");
	dfsan_label fp_label= dfsan_read_label(fp, sizeof(fp));
	printf("fp_label: %d\n", fp_label);
	dfsan_dump_label(fp_label);
	char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
		fread(buffer, sizeof(char), 2, fp);
		strcpy(dst, buffer);
		if ( (dst[0]-'0') %3 == 0 )
			printf("%s \n", dst);
		dfsan_label buffer_label = dfsan_read_label(buffer,sizeof(buffer));
		dfsan_label dst_label = dfsan_read_label(dst,sizeof(dst));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
		printf("dst_label: %d\n", dst_label);
		dfsan_dump_label(dst_label);
	}
	return 0;
}
