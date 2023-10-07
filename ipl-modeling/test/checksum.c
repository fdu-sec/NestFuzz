#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int checksum(const char* buf, int length) {
    int c = 1;
    if (length) do {
        c = (*buf++ & 0xff) ^ (c >> 8);
    } while (--length);
    return c;
}

char data[100] = {'\0'};
char *data_ptr = data;
void read_header()
{
    char header[10] = {'\0'};
    memcpy(header,data_ptr,8);
    printf("header%s\n",header);
    data_ptr += 8;
}

int hex2int(char *len_tmp)
{
  int len = 0;
  len = len_tmp[3] + len_tmp[2]*256 + len_tmp[1]*256*256 + len_tmp[0]*256*256*256;
  return len;
}

int main() 
{
    FILE *fp;
    fp = fopen("crafted-png", "rb");
    if (fp)
    {
        fread(data, sizeof(char), 72, fp);
        // printf("%x\n",*data_ptr);
        read_header();
        // printf("%x\n",*data_ptr);
        //3 chunk
        for (int i = 0; i < 3; ++i) {
            char len_tmp[5] = {'\0'};
            memcpy(len_tmp, data_ptr, 4);
            int length = hex2int(len_tmp);
            printf("length:%d\n",length);
            // printf("%x\n",*data_ptr);
            data_ptr += 8;
            int value  = 0;
            memcpy(&value, data_ptr+length,4);
            printf("value:%u\n",value);
            int cks = checksum(data_ptr,length);
            if (cks == value) {
                printf("cks eq:%d\n", cks);
            }
            printf("cks:%d\n", cks);
            while (length--) {
                data_ptr++;
            }
            
            // printf("%x\n",*data_ptr);
            data_ptr+=4;
            // printf("%x\n",*data_ptr);
        }
    }
    return 0;
}