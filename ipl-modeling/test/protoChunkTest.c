
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char data[100];
unsigned int unread_marker = 0;
int saw_SOI = 0;
char *cinfo;

typedef enum
{
  M_SOI = 0xd8,
  M_EOI = 0xd9,
  M_SOS = 0xda,
  M_DQT = 0xdb,

  M_APP0 = 0xe0,

  M_ERROR = 0x100
} JPEG_MARKER;

int first_marker(){ //2d815c6f
  int c = 0, c2 = 0;
  memcpy(&c, cinfo++, 1);
  memcpy(&c2, cinfo++, 1);
  if (c != 0xFF || c2 != (int)M_SOI) {
    printf("ERROR SOI MARKER!\n");
    exit(-1);
    return 0;
  }
  unread_marker = c2;
  return 1;
}

int next_marker(){ //6bd07ba6
  int c = 0;
  for (;;){
    memcpy(&c, cinfo++, 1);
    printf("c = %x\n",c);
    while (c != 0xFF) memcpy(&c, cinfo++, 1);
    memcpy(&c, cinfo++, 1);
    if (c != 0) break;
  }
  unread_marker = c;
  return 1;
}

int get_soi(){ //2317d0f0
  saw_SOI = 1;
  return 1;
}

int get_chunk()
{
  int _len = 0, len = 0;
  memcpy(&_len, cinfo, 2);
  memcpy(&len, cinfo + 1, 1);
  len = len + _len - _len;
  cinfo += 2;
  len -= 2;
  while (len > 0){
    char c = *cinfo++;
    printf("%02x ", c);
    len--;
  }
  printf("\n");
  return 1;
}

int read_markers() {
  for (;;) { //b69549b3
    if (unread_marker == 0) {
      if (!saw_SOI) {
        if (!first_marker()) return -1;
      } else {
        if (!next_marker()) return -1;
      }
    }
    switch (unread_marker) {
    case M_SOI:
      if (!get_soi()) return -1;
      break;
    case M_EOI:
      unread_marker = 0; /* processed the marker */
      return -1;
    case M_DQT:
      return -1;
      if (!get_chunk()) return -1;
      get_chunk();
      break;
    case M_APP0:
      if (!get_chunk()) return -1;
      break;
    default: /* must be DHP, EXP, JPGn, or RESn */
      printf("ERROR MARKER!\n");
    }
    unread_marker = 0;
  } /* end loop */
}

int main() {
  FILE *fp, *fp2;
  fp2 = fopen("file", "rb");
  fp = fopen("crafted-jpg", "rb");
  if (fp) {
    fread(data, sizeof(char), 59, fp);
    cinfo = data;
    read_markers();
  }
  fclose(fp);
  fclose(fp2);
  return 0;
}