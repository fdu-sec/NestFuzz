// gclang -O0 -fno-discard-value-names protoLoopTest.c -o protoLoopTest.gclang
// get-bc ./protoLoopTest.gclang
// llvm-dis protoLoopTest.gclang.bc -o -
// opt -load ../install/pass/libLoopHandlingPass.so --loop-handling-pass -load ../install/pass/libDFSanPass.so -dfsan_pass -chunk-dfsan-abilist=../install/rules/angora_abilist.txt -chunk-dfsan-abilist=../install/rules/dfsan_abilist.txt -S ./protoLoopTest.gclang.bc
// ../install/test-clang protoLoopTest.gclang.bc

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int A = 0;

int func(int x) {
    int y = 2;
	return x+y;
}

void loop(int x, char *buffer) {
	for (int i = 0; i < x; ++i) {
		printf("%d\n", buffer[i]);
	}
}


void loop2(int ch) {
	int x = 0;
	int y = 0;
	for (int i = 0; i < 5; ++i) {
		x +=i;
		for (int j = 0; j < 5; ++j) {
			y = y + x + ch;
		}
	}
	printf("loop2: %d\n",y);

}

void loop3(char* buffer) {
	for (int i = 0; i < 3; ++i) {
		printf("%c ", buffer[i]);
		for (int j = 0; j < 3 ; ++j) {
			for (int k = 0; k < 3; ++k) {
				printf("%c ", buffer[k]);
			}
			printf("%c ", buffer[j]);
		}
	}
	printf("\n");
}

void loop_func(char* buff) {
	for (int i = 0; i < 5; ++i) {
		int x = buff[i]-'0';
		func(x);
	}
}

void loop2_func() {// not taint
	int x = 0;
	for (int i = 0; i < 3; ++i) {
		for (int j = 0; j < 2; ++j) {
			x += i;
			x = func(x);
		}
	}
	printf("loop_func: %d\n", x);
}

void func2() {
	int y = 3;
	printf("func2: %d\n",func(y));
}


void loop_break(int x, char *buffer) {
	for (int i = 0; i < x; ++i) {
		if (buffer[i] == '1')
			break;
		if (buffer[i] == '2')
			break;
		printf("%d\n", buffer[i]);
	}
}


int main()
{
	FILE *fp;
	fp = fopen("file", "rb");
	char buffer[20];
	char dst[20];
	int ch = 0;
	fread(buffer, sizeof(char), 10, fp);
	ch = buffer[0] - '0';
	loop_break(5,buffer);
	/*
	loop(5, buffer);
	loop2(ch);
	loop3(buffer);
	loop_func(buffer);
	loop2_func();
	func2();
	*/
	return 0;
}

/*
49
50
51
52
53
loop2: 125
1 1 2 3 1 1 2 3 2 1 2 3 3 2 1 2 3 1 1 2 3 2 1 2 3 3 3 1 2 3 1 1 2 3 2 1 2 3 3 
loop_func: 9
func2: 5
*/
