#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Chunk
{
    uint32_t magic;
    uint8_t version_major;
    uint8_t version_minor;
    int32_t length;
    int32_t offset;
};

int32_t read_chunk(FILE *fp)
{
    struct Chunk chunk;
    uint32_t amt;
    amt = fread((char *)&chunk, 1, sizeof(chunk), fp);
    if (amt != sizeof(chunk))
    {
        printf("short read");
        exit(0);
    }
    printf("magic is %d\n", chunk.magic);
    printf("version_major is %d\n", chunk.version_major);
    printf("version_minor is %d\n", chunk.version_minor);
    printf("length is %d\n", chunk.length);
    printf("offset is %d\n", chunk.offset);
    return 0;
}

int32_t read_ng_chunk(FILE *fp)
{
    return 0;
}

int main()
{
    FILE *fp;
    fp = fopen("crafted-jpg", "rb");
    int32_t (*reader)(FILE * fp);
    reader = read_chunk;
    reader(fp);
    read_chunk(fp);
    fclose(fp);
    return 0;
}
