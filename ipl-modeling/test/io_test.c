#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../dfsan_rt/dfsan_interface.h"

#include <sys/types.h>    
#include <sys/stat.h>    
#include <fcntl.h>
#include <unistd.h>
#include <linux/fb.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <utmpx.h>

/*
../install/test-clang loopTest.c -o loopTest

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

int fd;
FILE *fp;

void foo() {
    for(int i = 0; i < 10; ++i)
        printf("%d\n",i);
}

void stat_test() {
  struct stat buf;
  stat("file", &buf);
  printf("file size = %ld\n", buf.st_size);
  dfsan_label stat_label = dfsan_read_label(&buf.st_size,sizeof(buf.st_size));
  printf("stat_label: %d\n", stat_label);
  dfsan_dump_label(stat_label);
}

void fstat_test(){
    struct stat buf;
    fstat(fd,&buf);
    printf("file size = %ld\n", buf.st_size);
    dfsan_label stat_label = dfsan_read_label(&buf.st_size,sizeof(buf.st_size));
    printf("stat_label: %d\n", stat_label);
    dfsan_dump_label(stat_label);
}

void lstat_test(){
    struct stat buf;
    lstat("file", &buf);
  	printf("file size = %ld\n", buf.st_size);
  	dfsan_label stat_label = dfsan_read_label(&buf.st_size,sizeof(buf.st_size));
  	printf("stat_label: %d\n", stat_label);
  	dfsan_dump_label(stat_label);
}


void fread_test(){
  char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
		// fread(buffer, sizeof(char), 2, fp);
		fread_unlocked(buffer,sizeof(char),2,fp);
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
}

void read_test(){
  char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    	read(fd,buffer,sizeof(char)*2);
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
}

void pread_test(){
  char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    pread(fd,buffer,sizeof(char)*2,2*i);
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
}

void fgetc_test(){
  	char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    // buffer[0] = fgetc(fp);
    // buffer[1] = fgetc(fp);
	buffer[0] = fgetc_unlocked(fp);
	buffer[1] = fgetc_unlocked(fp);
    // gets(buffer);
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
}

void fgetc_bug_test(){
  // 利用fgetc的情况下出现了一个bug 在tag的追加的时候出现了问题 一般的测试用例下没有问题
  char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    buffer[2*i] = fgetc(fp);
    buffer[2*i+1] = fgetc(fp);
	// buffer[2*i] = fgetc_unlocked(fp);
    // buffer[2*i+1] = fgetc_unlocked(fp);
    // gets(buffer);
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
}

// 用不了 c99标准
// void gets_test(){
//   char ch;
// 	char buffer[10];
// 	char dst[10];
// 	for (int i = 0; i < 4 ; ++i) {
//     gets(buffer);
// 		strcpy(dst, buffer);
// 		if ( (dst[0]-'0') %3 == 0 )
// 			printf("%s \n", dst);
// 		dfsan_label buffer_label = dfsan_read_label(buffer,sizeof(buffer));
// 		dfsan_label dst_label = dfsan_read_label(dst,sizeof(dst));
// 		printf("buffer_label: %d\n", buffer_label);
// 		dfsan_dump_label(buffer_label);
// 		printf("dst_label: %d\n", dst_label);
// 		dfsan_dump_label(dst_label);
// 	}
// }

void map_test(){
	char *buffer = (char *)mmap(0, 10, PROT_READ | PROT_WRITE, MAP_SHARED,fd, 0);
	for (int i = 0; i < 10 ; ++i) {
		dfsan_label buffer_label = dfsan_read_label(buffer+i,sizeof(buffer));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
	}
	munmap(buffer, 10);
	for (int i = 0; i < 10 ; ++i) {
		dfsan_label buffer_label = dfsan_read_label(buffer+i,sizeof(buffer));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
	}
}

void _IO_getc_test(){
	char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    	buffer[0] = _IO_getc(fp);
    	buffer[1] = _IO_getc(fp);
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
}

// 使用 ./iotest < file 来进行测试
void getchar_test(){
	char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    	buffer[0] = getchar();
    	buffer[1] = getchar();
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
}

void fgets_test(){
	char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    	fgets(buffer,3,fp);
    	// fgets_unlocked(buffer,3,fp);
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
}

void getutxent_test(){
	struct utmpx *u;
	if((u = getutxent()))
    {
        printf("%d %s %s %s \n", u->ut_type, u->ut_user, u->ut_line, u->ut_host);
		dfsan_label u_label = dfsan_read_label(u,sizeof(u));
		printf("u_label: %d\n", u_label);
		dfsan_dump_label(u_label);
    }
	
    endutxent();
}

void getline_test(){
	char *buffer = NULL;
	ssize_t n;
	size_t size;
	n=getline(&buffer,&size,fp);
	for (int i = 0; i < 10 ; ++i) {
		dfsan_label buffer_label = dfsan_read_label(buffer+i,sizeof(buffer));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
	}
}

void getdelim_test(){
	char *buffer = NULL;
	ssize_t n;
	size_t size;
	//此处在file文件中67之间插入了一个空格 便于测试
	// n=getdelim(&buffer,&size,' ',fp);
	n=__getdelim(&buffer,&size,' ',fp);
	for (int i = 0; i < 10 ; ++i) {
		dfsan_label buffer_label = dfsan_read_label(buffer+i,sizeof(buffer));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
	}
}

void xstat_test(){
	struct stat buf;
  	__xstat(1,"file", &buf);
  	printf("file size = %ld\n", buf.st_size);
  	dfsan_label stat_label = dfsan_read_label(&buf.st_size,sizeof(buf.st_size));
  	printf("stat_label: %d\n", stat_label);
  	dfsan_dump_label(stat_label);
}

void fxstat_test(){
	struct stat buf;
  	__fxstat(1, fd, &buf);
  	printf("file size = %ld\n", buf.st_size);
  	dfsan_label stat_label = dfsan_read_label(&buf.st_size,sizeof(buf.st_size));
  	printf("stat_label: %d\n", stat_label);
  	dfsan_dump_label(stat_label);
}

void lxstat_test(){
	struct stat buf;
  	__lxstat(1, "file", &buf);
  	printf("file size = %ld\n", buf.st_size);
  	dfsan_label stat_label = dfsan_read_label(&buf.st_size,sizeof(buf.st_size));
  	printf("stat_label: %d\n", stat_label);
  	dfsan_dump_label(stat_label);
}

int main()
{
	foo();
  // fopen
 	fp = fopen("file", "rb");
  // open fdopen
  	// fd = open("file",O_RDWR);
  	// fp = fdopen(fd, "r");
	dfsan_label fp_label= dfsan_read_label(fp, sizeof(fp));
	printf("fp_label: %d\n", fp_label);
	dfsan_dump_label(fp_label);

	getchar_test();

    fclose(fp);
	return 0;
}
