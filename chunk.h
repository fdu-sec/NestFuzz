#ifndef __CHUNK_H__
#define __CHUNK_H__

#include <stdint.h>


typedef struct Node {
  uint32_t start;
  uint32_t end;
  struct Node *next;
} Node;

typedef enum {
  length_meta,
  length_payload,
  offset_meta,
  offset_payload
} LEN_OFF;

typedef struct {
  struct Chunk *ptr;
  LEN_OFF type;
  uint32_t k;
  uint32_t b;  // if type <=1, length=kx+b;if type > 1 (offset),b is meaningless
  struct Cons *next;
} Cons;

typedef struct Chunk {
  uint32_t start;
  uint32_t end;
  uint8_t *id;
  uint8_t *type;
  struct Chunk *next;
  struct Chunk *prev;
  struct Chunk *child;
  struct Chunk *parent;
  struct Cons *cons;
} Chunk;

typedef struct Scope {
  struct Chunk *chunk;
  uint32_t start;
  uint32_t end;
  struct Scope *next;
} Scope;

typedef struct Enum {
  uint8_t *id;
  uint32_t start;
  uint32_t end;
  struct Enum *next;
  uint32_t cans_num;
  uint8_t *candidates[];
} Enum;

typedef struct Length {
  uint8_t *id;
  uint8_t *target_id;
  uint32_t start;
  uint32_t end;
  uint32_t target_start;
  uint32_t target_end;
  struct Length *next;
} Length;

typedef struct Offset {
  uint8_t *id;
  uint8_t *target_id;
  uint8_t abs;  // 1 or 0
  uint32_t start;
  uint32_t end;
  uint32_t target_start;
  uint32_t target_end;
  struct Offset *next;
} Offset;

typedef struct Constraint {
  uint32_t type;
  uint32_t start;
  uint32_t end;
  uint32_t target_start;
  uint32_t target_end;
  struct Constraint *next;
} Constraint;

typedef struct Track {
  struct Enum *enums;
  struct Length *lengths;
  struct Offset *offsets;
  struct Constraint *constraints;
  uint64_t enum_number;
} Track;

#endif  // !__CHUNK_H__