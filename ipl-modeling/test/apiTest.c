#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../dfsan_rt/dfsan_interface.h"

FILE *fp;

void offset_test(){
    char buffer[10];
    for(int i=0;i<4;i++){
        fread(buffer,sizeof(char),1,fp);
        int c = buffer[0]-'0';
        fseek(fp,c,SEEK_CUR);
    }
}

void checksum_test(){
    char buffer[10];
    fread(buffer,sizeof(char),10,fp);

    int loop = 1;
    while(loop){
        char c = buffer[0] + buffer[1]-'0' + buffer[2]-'0' + buffer[3]-'0';
        printf("%c %c\n", c, buffer[8]);
        if(c!=buffer[8]) loop=0;
    }
}

void cmp_test(){
    char buf1[10];
    fread(buf1, sizeof(char),5,fp);
    for(int i=0;i<5;i++){
        if((buf1[i]-'0')>1) i+=1;
    }
}

void switch_test(){
    char buf1[10];
    fread(buf1, sizeof(char),5,fp);
    for(int i=0;i<5;i++){
        switch(buf1[i]){
            case '0' : printf("case0\n");break;
            case '1' : printf("first\n");break;
            default: printf("else\n");break;
        }
    }
}

void cmpfn_test(){
    char buf1[10];
    char buf2[10];
    for(int i=0;i<10;i++){
        buf1[i]='\0';
        buf2[i]='\0';
    }
    for(int i=0;i<3;i++){
        fread(buf1, sizeof(char),2,fp);
        // dfsan_label buffer1 = dfsan_read_label(buf1,sizeof(buf1));
        fread(buf2, sizeof(char),2,fp);
        // dfsan_label buffer2 = dfsan_read_label(buf2,sizeof(buf2));
        printf("%s %s\n",buf1,buf2);
        // printf("%d %d\n",buffer1,buffer2);
        strcmp(buf1,"12");
        strcmp("34",buf2);
    }
}

void len0_test(){
    
    char lenbuf[10];
    fread(lenbuf,sizeof(char),5,fp);
    int len[3];
    len[0]=lenbuf[0]-'0';
    len[1]=lenbuf[1]-'0';
    len[2]=lenbuf[2]-'0';

    char buf1[10];
    for(int i=0;i<3;i++){
        fread(buf1, len[i],len[0],fp);
        dfsan_label buffer1 = dfsan_read_label(buf1,sizeof(buf1));
        dfsan_label len_lb = dfsan_read_label(len+i,sizeof(len[i]));
        printf("%s %d %d\n",buf1,buffer1,len_lb);
    }
}

void len1_test(){
    char buffer[20];
    fread(buffer,sizeof(char),20,fp);
    fseek(fp,0,SEEK_SET);

    char target[10];
    for(int i=0;i<10;i++) target[i]='\0';
    char lenbuf[10];
    int len;
    for(int i=0;i<3;i++){
        fread(lenbuf,sizeof(char),1,fp);
        len=lenbuf[0]-'0';
        // memcpy(target,buffer,len);
        strncpy(target,buffer,len);
        dfsan_label bufferlb = dfsan_read_label(target,sizeof(target));
        printf("%s %d\n",target,bufferlb);
    }
}

void len2_test(){
    int fd = fileno(fp);

    char lenbuf[10];
    read(fd,lenbuf,5);
    int len[3];
    len[0]=lenbuf[0]-'0';
    len[1]=lenbuf[1]-'0';
    len[2]=lenbuf[2]-'0';

    char buf1[10];
    for(int i=0;i<10;i++) buf1[i]='\0';
    for(int i=0;i<3;i++){
        read(fd,buf1,len[i]);
        dfsan_label buffer1 = dfsan_read_label(buf1,sizeof(buf1));
        dfsan_label len_lb = dfsan_read_label(len+i,sizeof(len[i]));
        printf("%s %d %d\n",buf1,buffer1,len_lb);
    }
}

int main()
{
 	fp = fopen("file", "rb");
    
    checksum_test();

    fclose(fp);
	return 0;
}