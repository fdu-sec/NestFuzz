#include "structure_mutation.h"

int32_t get_json_start(const cJSON *chunk) {
  if (cJSON_HasObjectItem(chunk, "start")) {
    return cJSON_GetObjectItemCaseSensitive(chunk, "start")->valueint;
  }
  return -1;
}

int32_t get_json_end(const cJSON *chunk) {
  if (cJSON_HasObjectItem(chunk, "end")) {
    return cJSON_GetObjectItemCaseSensitive(chunk, "end")->valueint;
  }
  return -1;
}

u8 *get_json_type(const cJSON *chunk) {
  if (cJSON_HasObjectItem(chunk, "type")) {
    return cJSON_GetObjectItemCaseSensitive(chunk, "type")->valuestring;
  }
  return NULL;
}

Chunk *get_tree(cJSON *cjson_head) {
  Chunk *head, *root, *iter;
  u32 end;
  head = json_to_tree(cjson_head);
  if (head->next) {
    root = ck_alloc(sizeof(Chunk));
    root->child = head;
    root->start = head->start;
    iter = head;
    while (iter != NULL) {
      iter->parent = root;
      end = iter->end;
      iter = iter->next;
    }
    root->end = end;
    root->id = "root";
    root->cons = NULL;
    root->parent = root->next = root->prev = NULL;
  } else {
    root = head;
  }
  return root;
}

u32 htoi(u8 s[]) {
  u32 i;
  u32 n = 0;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    i = 2;
  } else {
    i = 0;
  }
  for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') ||
         (s[i] >= 'A' && s[i] <= 'Z');
       ++i) {
    if (tolower(s[i]) > '9') {
      n = 16 * n + (10 + tolower(s[i]) - 'a');
    } else {
      n = 16 * n + (tolower(s[i]) - '0');
    }
  }
  return n;
}

uint8_t *itoh(uint32_t num) {
  uint8_t *buff;
  buff = ck_alloc(3);
  if (num / 16 < 10) {
    buff[0] = num / 16 + '0';
  } else {
    buff[0] = num / 16 - 10 + 'A';
  }
  if (num % 16 < 10) {
    buff[1] = num % 16 + '0';
  } else {
    buff[1] = num % 16 - 10 + 'A';
  }
  buff[2] = '\0';
  return buff;
}

uint8_t *candidate_reverse(char *str) {
  uint8_t *delim, *part, *candi, *buffer[1024], *tmp;
  int32_t num, i;
  delim = ", ";
  part = strtok(str, delim);
  num = 0;
  while (part != NULL) {
    buffer[num] = part;
    num++;
    part = strtok(NULL, delim);
  }
  candi = NULL;
  if (num > 0) {
    candi = alloc_printf("%s", buffer[num - 1]);
    for (i = num - 2; i >= 0; i--) {
      tmp = candi;
      candi = alloc_printf("%s, %s", tmp, buffer[i]);
      ck_free(tmp);
    }
  }
  ck_free(str);
  return candi;
}

uint8_t *parse_candidate(uint8_t *str, u32 *len) {
  uint8_t *delim, *part, *candi, c, buffer[1024];
  uint32_t num, i;
  delim = ", ";
  u8 *tmp = alloc_printf("%s", str);
  part = strtok(tmp, delim);
  i = 0;
  while (part != NULL) {
    num = htoi(part);
    c = num;
    buffer[i] = c;
    i++;
    part = strtok(NULL, delim);
  }
  candi = ck_alloc(i + 1);
  *len = i;
  memcpy(candi, buffer, i);
  candi[i] = '\0';
  ck_free(tmp);
  return candi;
}

cJSON *tree_to_json(Chunk *chunk_head) {
  Chunk *iter;
  iter = chunk_head;
  cJSON *json_head;
  json_head = cJSON_CreateObject();
  while (iter != NULL) {
    cJSON *cjson = cJSON_CreateObject();
    cJSON_AddNumberToObject(cjson, "start", iter->start);
    cJSON_AddNumberToObject(cjson, "end", iter->end);
    if (iter->child != NULL) {
      cJSON_AddItemToObject(cjson, "child", tree_to_json(iter->child));
    }
    cJSON_AddItemToObject(json_head, iter->id, cjson);
    iter = iter->next;
  }
  return json_head;
}

cJSON *track_to_json(Track *track) {
  cJSON *json_head;
  json_head = cJSON_CreateObject();
  Enum *enum_iter = track->enums;
  Length *len_iter = track->lengths;
  Offset *off_iter = track->offsets;
  Constraint *cons_iter = track->constraints;
  u32 index = 0;
  while (enum_iter) {
    cJSON *cjson = cJSON_CreateObject();
    cJSON_AddNumberToObject(cjson, "start", enum_iter->start);
    cJSON_AddNumberToObject(cjson, "end", enum_iter->end);
    cJSON_AddStringToObject(cjson, "type", "enum");
    cJSON_AddNumberToObject(cjson, "num", enum_iter->cans_num / 2);
    cJSON *can_json = cJSON_CreateObject();
    for (u32 i = 0; i < enum_iter->cans_num / 2; i++) {
      u8 *cand_id = alloc_printf("%d", i);
      cJSON_AddStringToObject(can_json, cand_id, enum_iter->candidates[i]);
      ck_free(cand_id);
    }
    cJSON_AddItemToObject(cjson, "candidates", can_json);
    // u8 *enum_id = alloc_printf("enum_%d", index);
    cJSON_AddItemToObject(json_head, enum_iter->id, cjson);
    // ck_free(enum_id);
    enum_iter = enum_iter->next;
    index++;
  }
  while (len_iter) {
    cJSON *cjson = cJSON_CreateObject();
    cJSON_AddNumberToObject(cjson, "start", len_iter->start);
    cJSON_AddNumberToObject(cjson, "end", len_iter->end);
    cJSON_AddStringToObject(cjson, "type", "length");
    cJSON *target_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(target_json, "start", len_iter->target_start);
    cJSON_AddNumberToObject(target_json, "end", len_iter->target_end);
    cJSON_AddItemToObject(cjson, len_iter->target_id, target_json);
    // u8 *len_id = alloc_printf("len_%d", index);
    cJSON_AddItemToObject(json_head, len_iter->id, cjson);
    // ck_free(len_id);
    len_iter = len_iter->next;
    index++;
  }
  while (off_iter) {
    cJSON *cjson = cJSON_CreateObject();
    cJSON_AddNumberToObject(cjson, "start", off_iter->start);
    cJSON_AddNumberToObject(cjson, "end", off_iter->end);
    cJSON_AddStringToObject(cjson, "type", "offset");
    cJSON *target_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(target_json, "start", off_iter->target_start);
    cJSON_AddNumberToObject(target_json, "end", off_iter->target_end);
    cJSON_AddItemToObject(cjson, off_iter->target_id, target_json);
    //u8 *off_id = alloc_printf("off_%d", index);
    cJSON_AddItemToObject(json_head, off_iter->id, cjson);
    //ck_free(off_id);
    off_iter = off_iter->next;
    index++;
  }
  while (cons_iter) {
    cons_iter = cons_iter->next;
    index++;
  }
  return json_head;
}

void tree_add_map(Chunk *head, HashMap map) {
  Chunk *iter = head;
  while (iter != NULL) {
    map->put(map, iter->id, iter);
    if (iter->child != NULL) {
      tree_add_map(iter->child, map);
    }
    iter = iter->next;
  }
}

void free_tree(Chunk *head, Boolean recurse) {
  if (head == NULL) {
    return;
  }
  Chunk *iter = NULL;
  while (head != NULL) {
    if (recurse) {
      iter = head->next;
    } else {
      iter = NULL;
    }
    ck_free(head->id);
    head->id = NULL;
    if (head->cons != NULL) {
      ck_free(head->cons);
    }
    if (head->child) {
      free_tree(head->child, True);
    }
    ck_free(head);
    head = iter;
  }
}

void free_enum(Enum *node) {
  u32 i;
  ck_free(node->id);
  for (i = 0; i < node->cans_num; i++) {
    ck_free(node->candidates[i]);
  }
  ck_free(node);
}

void free_track(Track *track) {
  Enum *enum_next = NULL;
  Constraint *cons_next = NULL;
  Length *len_next = NULL;
  Offset *offset_next = NULL;
  if (track == NULL) {
    return;
  }
  while (track->offsets != NULL) {
    offset_next = track->offsets->next;
    ck_free(track->offsets->id);
    ck_free(track->offsets->target_id);
    ck_free(track->offsets);
    track->offsets = offset_next;
  }

  while (track->enums != NULL) {
    enum_next = track->enums->next;
    free_enum(track->enums);
    track->enums = enum_next;
  }

  while (track->constraints != NULL) {
    cons_next = track->constraints->next;
    ck_free(track->constraints);
    track->constraints = cons_next;
  }

  while (track->lengths != NULL) {
    len_next = track->lengths->next;
    ck_free(track->lengths->id);
    ck_free(track->lengths->target_id);
    ck_free(track->lengths);
    track->lengths = len_next;
  }
  ck_free(track);
}

void number_add(u8 *buf, u32 start, u32 len, u32 num) {
  if (len == 1) {
    *(u8 *)(buf + start) += num;
  } else if (len == 2) {
    if (UR(2)) {
      *(u16 *)(buf + start) += num;
    } else {
      *(u16 *)(buf + start) = SWAP16(SWAP16(*(u16 *)(buf + start)) + num);
    }
  } else if (len == 4) {
    if (UR(2)) {
      *(u32 *)(buf + start) += num;
    } else {
      *(u32 *)(buf + start) = SWAP32(SWAP32(*(u32 *)(buf + start)) + num);
    }
  }
}

void number_subtract(u8 *buf, u32 start, u32 len, u32 num) {
  if (len == 1) {
    *(u8 *)(buf + start) -= num;
  } else if (len == 2) {
    if (UR(2)) {
      *(u16 *)(buf + start) -= num;
    } else {
      *(u16 *)(buf + start) = SWAP16(SWAP16(*(u16 *)(buf + start)) - num);
    }
  } else if (len == 4) {
    if (UR(2)) {
      *(u32 *)(buf + start) -= num;
    } else {
      *(u32 *)(buf + start) = SWAP32(SWAP32(*(u32 *)(buf + start)) - num);
    }
  }
}

void number_set_interesting(u8 *buf, u32 start, u32 len, u32 index) {
  if (len == 1) {
    buf[start] = interesting_8[index];
  } else if (len == 2) {
    if (UR(2)) {
      *(u16 *)(buf + start) = interesting_16[index];
    } else {
      *(u16 *)(buf + start) = SWAP16(interesting_16[index]);
    }
  } else if (len == 4) {
    if (UR(2)) {
      *(u32 *)(buf + start) = interesting_32[index];
    } else {
      *(u32 *)(buf + start) = SWAP32(interesting_32[index]);
    }
  }
}

Chunk *get_random_chunk(Chunk *head) {
  Chunk *reserve, *iter;
  u32 count, rand;
  reserve = NULL;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

Enum *get_random_enum(Enum *head) {
  Enum *reserve, *iter;
  u32 count, rand;
  reserve = NULL;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

Length *get_random_length(Length *head) {
  Length *reserve, *iter;
  u32 count, rand;
  reserve = NULL;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

Offset *get_random_offset(Offset *head) {
  Offset *reserve, *iter;
  reserve = NULL;
  u32 count, rand;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

Constraint *get_random_constraint(Constraint *head) {
  Constraint *reserve, *iter;
  u32 count, rand;
  reserve = NULL;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

cJSON *get_json(const u8 *path) {
  cJSON *cjson_head;
  s32 fd;
  u8 *in_buf;
  struct stat st;
  s32 n;
  if (lstat(path, &st)) {
    PFATAL("Lstat read '%s'", path);
  }
  fd = open(path, O_RDONLY);
  if (fd < 0) {
    PFATAL("open failed '%s' errno is %d, %s, fd is %d",
           path, errno, strerror(errno), fd);
  }
  in_buf = ck_alloc(st.st_size);
  n = read(fd, in_buf, st.st_size);
  if (n < st.st_size) {
    PFATAL("Short read '%s' n is %d, size is %ld, errno is %d, %s, fd is %d", path, n, st.st_size, errno, strerror(errno), fd);
  }
  cjson_head = cJSON_ParseWithLength(in_buf, st.st_size);
  // if (cjson_head == NULL) {
  //   PFATAL("Unable to parse '%s'", path);
  // }
  close(fd);
  ck_free(in_buf);
  return cjson_head;
}

cJSON *get_structure_json(const u8 *path, const u8 *suffix) {
  cJSON *cjson_head;
  struct stat st;
  u8 *file_name = basename((char *)path);
  u8 *structure_file = alloc_printf("%s/structure/%s%s", out_dir, file_name, suffix);
  if (!lstat(structure_file, &st)) {
    cjson_head = get_json(structure_file);
    ck_free(structure_file);
    queue_cur->was_inferred = 1;
    return cjson_head;
  }
  ck_free(structure_file);
  structure_file = alloc_printf("%s/queue/%s%s", out_dir, file_name, suffix);
  if (!lstat(structure_file, &st)) {
    cjson_head = get_json(structure_file);
    ck_free(structure_file);
    queue_cur->was_inferred = 0;
    return cjson_head;
  }
  ck_free(structure_file);
  return NULL;
}

Chunk *json_to_tree(cJSON *cjson_head) {
  uint32_t chunk_num = cJSON_GetArraySize(cjson_head);
  Chunk *head, *top, *iter;
  head = top = NULL;
  for (uint32_t i = 0; i < chunk_num; i++) {
    cJSON *chunk = cJSON_GetArrayItem(cjson_head, i);
    if (!chunk) {
      continue;
    }
    int32_t start = get_json_start(chunk);
    int32_t end = get_json_end(chunk);
    if (start < 0 || end < 0) {
      continue;
    }
    Chunk *node = ck_alloc(sizeof(Chunk));
    node->start = start;
    node->end = end;
    node->id = (uint8_t *)ck_alloc(strlen(chunk->string) + 1);
    strcpy(node->id, chunk->string);
    node->parent = node->child = node->prev = node->next = NULL;
    node->cons = NULL;
    if (top) {
      top->next = node;
      node->prev = top;
      top = node;
    } else {
      head = top = node;
    }
    if (cJSON_HasObjectItem(chunk, "child")) {
      top->child =
          json_to_tree(cJSON_GetObjectItemCaseSensitive(chunk, "child"));
      iter = top->child;
      while (iter) {
        iter->parent = top;
        iter = iter->next;
      }
    }
  }
  return head;
}

Boolean is_inferred(u8 *path) {
  struct stat st;
  u8 *file_name = basename((char *)path);
  u8 *structure_file = alloc_printf("%s/structure/%s%s", out_dir, file_name, ".json");
  if (!lstat(structure_file, &st)) {
    ck_free(structure_file);
    return True;
  }
  ck_free(structure_file);
  return False;
}

Chunk *parse_struture_file(u8 *path) {
  cJSON *cjson_head = get_structure_json(path, ".json");
  if (cjson_head == NULL) {
    return NULL;
  }
  Chunk *head = json_to_tree(cjson_head);
  cJSON_Delete(cjson_head);
  return head;
}

Track *parse_constraint_file(u8 *path) {
  cJSON *cjson_head = get_structure_json(path, ".track");
  if (cjson_head == NULL) {
    return NULL;
  }
  u32 num;
  num = cJSON_GetArraySize(cjson_head);
  Track *track;
  Enum *enum_top = NULL;
  Offset *offset_top = NULL;
  Length *length_top = NULL;
  // Constraint *cons_top = NULL;
  track = ck_alloc(sizeof(struct Track));
  track->constraints = NULL;
  track->lengths = NULL;
  track->offsets = NULL;
  track->enums = NULL;
  track->enum_number = 0;
  for (u32 i = 0; i < num; i++) {
    cJSON *item = cJSON_GetArrayItem(cjson_head, i);
    if (cJSON_HasObjectItem(item, "type")) {
      char *type = cJSON_GetObjectItemCaseSensitive(item, "type")->valuestring;
      if (strcmp(type, "enum") == 0) {
        u32 cans_num = cJSON_GetObjectItemCaseSensitive(item, "num")->valueint;
        Enum *enum_chunk =
            ck_alloc(sizeof(struct Enum) + cans_num * 2 * sizeof(uint8_t *));
        enum_chunk->start =
            cJSON_GetObjectItemCaseSensitive(item, "start")->valueint;
        enum_chunk->end =
            cJSON_GetObjectItemCaseSensitive(item, "end")->valueint;
        enum_chunk->cans_num = cans_num * 2;
        enum_chunk->next = NULL;
        enum_chunk->id = (uint8_t *)ck_alloc(strlen(item->string) + 1);
        strcpy(enum_chunk->id, item->string);
        cJSON *cans_json = cJSON_GetObjectItemCaseSensitive(item, "candidates");
        for (u32 j = 0; j < cJSON_GetArraySize(cans_json); j++) {
          char *candidate =
              cJSON_GetStringValue(cJSON_GetArrayItem(cans_json, j));
          enum_chunk->candidates[j] = ck_alloc(strlen(candidate) + 1);
          strcpy(enum_chunk->candidates[j], candidate);
        }
        if (enum_top) {
          enum_top->next = enum_chunk;
          enum_top = enum_chunk;
        } else {
          track->enums = enum_top = enum_chunk;
        }
        track->enum_number++;
      }
      if (strcmp(type, "length") == 0) {
        Length *length_chunk = ck_alloc(sizeof(struct Length));
        length_chunk->start =
            cJSON_GetObjectItemCaseSensitive(item, "start")->valueint;
        length_chunk->end =
            cJSON_GetObjectItemCaseSensitive(item, "end")->valueint;
        length_chunk->id = (uint8_t *)ck_alloc(strlen(item->string) + 1);
        strcpy(length_chunk->id, item->string);
        cJSON *target = cJSON_GetArrayItem(item, cJSON_GetArraySize(item) - 1);
        length_chunk->target_start =
            cJSON_GetObjectItemCaseSensitive(target, "start")->valueint;
        length_chunk->target_end =
            cJSON_GetObjectItemCaseSensitive(target, "end")->valueint;
        length_chunk->target_id = (uint8_t *)ck_alloc(strlen(target->string) + 1);
        strcpy(length_chunk->target_id, target->string);
        length_chunk->next = NULL;
        if (length_top) {
          length_top->next = length_chunk;
          length_top = length_chunk;
        } else {
          track->lengths = length_top = length_chunk;
        }
      }
      if (strcmp(type, "offset") == 0) {
        Offset *offset_chunk = ck_alloc(sizeof(struct Offset));
        offset_chunk->start =
            cJSON_GetObjectItemCaseSensitive(item, "start")->valueint;
        offset_chunk->end =
            cJSON_GetObjectItemCaseSensitive(item, "end")->valueint;
        offset_chunk->id = (uint8_t *)ck_alloc(strlen(item->string) + 1);
        strcpy(offset_chunk->id, item->string);
        cJSON *target = cJSON_GetArrayItem(item, cJSON_GetArraySize(item) - 1);
        offset_chunk->target_start =
            cJSON_GetObjectItemCaseSensitive(target, "start")->valueint;
        offset_chunk->target_end =
            cJSON_GetObjectItemCaseSensitive(target, "end")->valueint;
        offset_chunk->target_id = (uint8_t *)ck_alloc(strlen(target->string) + 1);
        strcpy(offset_chunk->target_id, target->string);
        offset_chunk->next = NULL;
        if (offset_top) {
          offset_top->next = offset_chunk;
          offset_top = offset_chunk;
        } else {
          track->offsets = offset_top = offset_chunk;
        }
      }
      if (strcmp(type, "constraint") == 0) {
      }
    } else {
      continue;
    }
  }
  enum_top = track->enums;
  while (enum_top) {
    num = enum_top->cans_num / 2;
    for (u32 i = 0; i < num; i++) {
      enum_top->candidates[i + num] =
          ck_alloc(strlen(enum_top->candidates[i]) + 1);
      strcpy(enum_top->candidates[i + num], enum_top->candidates[i]);
      enum_top->candidates[i + num] =
          candidate_reverse(enum_top->candidates[i + num]);
    }
    enum_top = enum_top->next;
  }
  cJSON_Delete(cjson_head);
  return track;
}

Boolean chunk_overleap(Chunk *chunk1, Chunk *chunk2) {
  if (chunk1->end <= chunk2->start || chunk1->start >= chunk2->end) {
    return False;
  }
  return True;
}

u8 *copy_and_insert(u8 *buf, u32 *len, u32 insert_at, u32 copy_start,
                    u32 copy_len) {
  u8 *new_buf;
  new_buf = ck_alloc(*len + copy_len);

  memcpy(new_buf, buf, insert_at);
  memcpy(new_buf + insert_at, buf + copy_start, copy_len);
  memcpy(new_buf + insert_at + copy_len, buf + insert_at, *len - insert_at);

  *len += copy_len;
  ck_free(buf);
  return new_buf;
}

u8 *insert_chunk(u8 *buf, u32 *len, HashMap map, u8 *insert_id, u8 *copy_id,
                 Boolean after) {
  uint8_t *new_buf;
  uint32_t insert_at;
  Chunk *chunk_insert = map->get(map, insert_id);
  Chunk *chunk_copy = map->get(map, copy_id);
  // if(chunk_copy->end - chunk_copy->start > *len / 4 && UR(100) < 75) {
  //   return buf;
  // }
  if(chunk_copy->end - chunk_copy->start > *len) {
    return buf;
  }
  insert_at = after ? chunk_insert->start : chunk_insert->end;
  if (insert_at > *len || chunk_copy->start > *len || chunk_copy->end > *len) {
    return buf;
  }
  new_buf =
      copy_and_insert(buf, len, insert_at, chunk_copy->start, chunk_copy->end - chunk_copy->start);
  return new_buf;
}

u8 *delete_data(u8 *buf, u32 *len, u32 delete_start, u32 delete_len) {
  u8 *new_buf;
  new_buf = ck_alloc(*len - delete_len);
  memcpy(new_buf, buf, delete_start);
  memcpy(new_buf + delete_start, buf + delete_start + delete_len,
         *len - delete_start - delete_len);
  *len -= delete_len;
  ck_free(buf);
  return new_buf;
}

u8 *delete_chunk(u8 *buf, u32 *len, HashMap map, u8 *id) {
  Chunk *chunk_delete = map->get(map, id);
  if (chunk_delete == NULL || chunk_delete->start > *len ||
      chunk_delete->end > *len) {
    return buf;
  }
  if(chunk_delete->end - chunk_delete->start >= *len) {
    return buf;
  }
  return delete_data(buf, len, chunk_delete->start,
                     chunk_delete->end - chunk_delete->start);
}

void get_exchange_chunks(uint32_t chunk_num, uint8_t **all_chunks, HashMap map,
                         Chunk **chunks) {
  uint32_t index1 = UR(chunk_num);
  // uint32_t index2 = UR(chunk_num);
  Chunk *chunk_left, *chunk_right, *temp;
  chunk_left = map->get(map, all_chunks[index1]);
  // chunk_right = map->get(map, all_chunks[index2]);
  if (chunk_left == NULL) {
    return;
  }
  // if (chunk_left->parent == NULL) {
  //   return;
  // }
  chunk_left = get_random_chunk(chunk_left->parent->child);
  chunk_right = get_random_chunk(chunk_left->parent->child);
  if (chunk_overleap(chunk_left, chunk_right)) {
    return;
  }
  if (strcmp(chunk_left->id, chunk_right->id) == 0) {
    return;
  }
  if (chunk_left->end >= chunk_right->end) {
    temp = chunk_left;
    chunk_left = chunk_right;
    chunk_right = temp;
  }
  chunks[0] = chunk_left;
  chunks[1] = chunk_right;
}

uint8_t *exchange_chunk(uint8_t *buf, uint32_t len, Chunk *chunk_left,
                        Chunk *chunk_right) {
  uint8_t *new_buf;
  if (chunk_left == NULL || chunk_left->parent == NULL) {
    return buf;
  }
  if (chunk_left->start > len || chunk_left->end > len ||
      chunk_right->start > len || chunk_right->end > len) {
    return buf;
  }
  new_buf = ck_alloc(len);
  memcpy(new_buf, buf, chunk_left->start);
  memcpy(new_buf + chunk_left->start, buf + chunk_right->start,
         chunk_right->end - chunk_right->start);
  memcpy(new_buf + chunk_left->start + chunk_right->end - chunk_right->start,
         buf + chunk_left->end, chunk_right->start - chunk_left->end);
  memcpy(new_buf + chunk_left->start + chunk_right->end - chunk_left->end,
         buf + chunk_left->start, chunk_left->end - chunk_left->start);
  memcpy(new_buf + chunk_right->end, buf + chunk_right->end,
         len - chunk_right->end);
  ck_free(buf);
  return new_buf;
}

void struct_describing_stage(char **argv, u8 *buf, u32 len, Chunk *tree,
                        Track *track) {
  u8 **all_chunks;
  u32 chunk_num = 0, out_len;
  u32 stage_max, stage_cur, i, perf_score = 100;
  u64 orig_hit_cnt, new_hit_cnt, struct_havoc_queued;
  u8 *out_buf;
  Enum *enum_field = NULL;
  Length *len_field = NULL;
  Offset *offset_field = NULL;
  out_len = len;
  out_buf = ck_alloc(len);
  memcpy(out_buf, buf, len);
  HashMap map = createHashMap(NULL, NULL);
  tree_add_map(tree->child, map);
  all_chunks = ck_alloc(map->size * sizeof(u8 *));
  HashMapIterator map_iter = createHashMapIterator(map);
  while (hasNextHashMapIterator(map_iter)) {
    map_iter = nextHashMapIterator(map_iter);
    all_chunks[chunk_num] = map_iter->entry->key;
    chunk_num++;
  }

  perf_score = calculate_score(queue_cur);

  stage_name = "struct_describing";
  stage_short = "chunkFuzzer1";
  stage_max = HAVOC_CYCLES * perf_score / havoc_div / 100;


  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;
  stage_cur = 0;

  orig_hit_cnt = queued_paths + unique_crashes;
  struct_havoc_queued = queued_paths;
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
      u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));
      for (i = 0; i < use_stacking; i++) {
      u32 num;
      num = UR(3 + ((track == NULL) ? 0 : 14));
      //SAYF("#Before mutate num is %d, out_len is %d\n", num, out_len);
      switch (num) {
        case 0: {
          /* Randomly copy one chunk and insert before/after random chunk */
          out_buf = insert_chunk_mutator(out_buf, &out_len, map, all_chunks, chunk_num);
          break;
        };
        case 1: {
          /* Randomly delete one chunk */
          out_buf = delete_chunk_mutator(out_buf, &out_len, map, all_chunks, chunk_num);
          break;
        };
        case 2: {
          /* Randomly exchange two chunks */
          out_buf = exchange_chunk_mutator(out_buf, &out_len, map, all_chunks, chunk_num);
          break;
        }
        case 3: {
          enum_field = get_random_enum(track->enums);
          out_buf = enum_insert_mutator(out_buf, &out_len, enum_field, map);
        }
        case 4: {
          enum_field = get_random_enum(track->enums);
          out_buf = enum_delete_mutator(out_buf, &out_len, enum_field, map);
        }
        case 5: {
          enum_field = get_random_enum(track->enums);
          out_buf = enum_exchange_mutator(out_buf, &out_len, enum_field, map);
        }
        case 6: {
          out_buf = high_order_structure_mutator(out_buf, &out_len, map, tree);
        }
        case 7: {
          /* Randomly replace one enum field to a legal candidate */
          enum_field = get_random_enum(track->enums);
          if(enum_field == NULL) {
            break;
          }
          out_buf = enum_mutator(out_buf, out_len, enum_field, UR(enum_field->cans_num));
          break;
        }
        case 8: {
          /* Randomly add to length field, random endian */
          len_field = get_random_length(track->lengths);
          out_buf = increase_len_mutator(out_buf, out_len, len_field, UR(out_len));
        }
        case 9: {
          /* Randomly add to offset field, random endian */
          offset_field = get_random_offset(track->offsets);
          out_buf = increase_offset_mutator(out_buf, out_len, offset_field, UR(out_len));
        }
        case 10: {
          /* Randomly subtract to length field, random endian */
          len_field = get_random_length(track->lengths);
          out_buf = decrease_len_mutator(out_buf, out_len, len_field, UR(out_len));
        }
        case 11: {
          /* Randomly subtract to offset field, random endian */
          offset_field = get_random_offset(track->offsets);
          out_buf = decrease_offset_mutator(out_buf, out_len, offset_field, UR(out_len));
        }
        case 12: {
          /* Randomly set length to interesting value, random endian */
          len_field = get_random_length(track->lengths);
          if(len_field == NULL) {
            break;
          }
          u32 field_len = len_field->end - len_field->start;
          u32 interest_index = 0;
          if (field_len == 1) {
            interest_index = UR(sizeof(interesting_8));
          } else if (field_len == 2) {
            interest_index = UR(sizeof(interesting_16) / 2);
          } else if (field_len == 4) {
            interest_index = UR(sizeof(interesting_32) / 4);
          } else {
            break;
          }
          out_buf = set_len_mutator(out_buf, out_len, len_field, interest_index);
          break;
        }
        case 13: {
          /* Randomly set offset to interesting value, random endian */
          offset_field = get_random_offset(track->offsets);
          if(offset_field == NULL) {
            break;
          }
          u32 field_len = offset_field->end - offset_field->start;
          u32 interest_index = 0;
          if (field_len == 1) {
            interest_index = UR(sizeof(interesting_8));
          } else if (field_len == 2) {
            interest_index = UR(sizeof(interesting_16) / 2);
          } else if (field_len == 4) {
            interest_index = UR(sizeof(interesting_32) / 4);
          } else {
            break;
          }
          out_buf = set_offset_mutator(out_buf, out_len, offset_field, interest_index);
          break;
        }
        case 14: {
          /* Randomly insert data to length payloads */
          len_field = get_random_length(track->lengths);
          out_buf = insert_len_payload_mutator(out_buf, &out_len, len_field);
          break;
        }
        case 15: {
          /* Randomly insert data to offset payloads */
          offset_field = get_random_offset(track->offsets);
          out_buf = insert_offset_payload_mutator(out_buf, &out_len, offset_field);
          break;
        }
        case 16: {
          /* Randomly delete data from offset payloads */
          len_field = get_random_length(track->lengths);
          out_buf = delete_len_payload_mutator(out_buf, &out_len, len_field);
          break;
        }
        case 17: {
          /* Randomly delete data from offset payloads */
          offset_field = get_random_offset(track->offsets);
          out_buf = delete_offset_payload_mutator(out_buf, &out_len, offset_field);
          break;
        }
      }
      //SAYF("#After mutate num is %d, out_len is %d\n", num, out_len);
    }

    if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
      goto exit_struct_havoc_stage;

    if (out_len < len) {
      out_buf = ck_realloc(out_buf, len);
    }
    out_len = len;
    memcpy(out_buf, buf, len);

    if (queued_paths != struct_havoc_queued) {
      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max *= 2;
        perf_score *= 2;
      }

      struct_havoc_queued = queued_paths;
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_STRUCT_DESCRIB] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_STRUCT_DESCRIB] += stage_max;

exit_struct_havoc_stage:

  freeHashMapIterator(&map_iter);
  map->clear(map);
  free(map);
  ck_free(all_chunks);
  ck_free(out_buf);
}

void constraint_aware_stage(char **argv, u8 *buf, u32 len, Chunk *tree,
                            Track *track) {
  if (track == NULL) {
    return;
  }
  u32 out_len;
  // u32 stage_max, stage_cur, index1, index2;
  int32_t i;
  u8 *out_buf;
  Enum *enum_iter;
  Length *length_iter;
  Offset *offset_iter;
  Constraint *cons_iter;
  u64 orig_hit_cnt, new_hit_cnt;
  HashMap map = createHashMap(NULL, NULL);
  out_len = len;
  out_buf = ck_alloc(len);
  memcpy(out_buf, buf, len);
  tree_add_map(tree->child, map);
  stage_name = "describing aware";
  stage_short = "chunkFuzzer2";
  orig_hit_cnt = queued_paths + unique_crashes;
  stage_max = 0;
  /* Mutation enum field, repalce with legal candidates */
  enum_iter = track->enums;
  /* TODO: avoid too much enums */
  save_enum_number = (save_enum_number + track->enum_number) / 2;
  if (save_enum_number > 512) {
    save_enum_number = 512;
  }
  if (save_enum_number == 0) {
    save_enum_number = 100;
  }
  u32 threshold = track->enum_number / save_enum_number;
  if (threshold == 0) {
    threshold = 1;
  }
  while (enum_iter != NULL) {
    /* TODO: avoid too much enums */
    if(threshold > 1 && UR(threshold) != 0) {
      enum_iter = enum_iter->next;
      continue;
    }
    u32 last_len = 0, stage_cur_byte;
    for (i = 0; i < enum_iter->cans_num; i++) {
      last_len = 0;
      u8 *candi_str = parse_candidate(enum_iter->candidates[i], &last_len);
      stage_cur_byte = enum_iter->start;
      if (stage_cur_byte < 0 || stage_cur_byte > out_len ||
          (stage_cur_byte + last_len) > out_len) {
        break;
      }
      if ((enum_iter->end - enum_iter->start) < last_len) {
        break;
      }
      /* new testcase */
      memcpy(out_buf + stage_cur_byte, candi_str, last_len);

      /*save testcase if interesting */
      if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
        goto exit_describing_aware_stage;

      /* Restore all the clobbered memory */
      memcpy(out_buf + stage_cur_byte, buf + stage_cur_byte, last_len);

      ck_free(candi_str);
      stage_max++;
    }
    if (UR(enum_iter->cans_num) <= enum_iter->cans_num / 2) {
      for(i = 0; i < enum_iter->cans_num / 2; i++) {
        switch(UR(3)) {
          case 0: {
            out_buf = enum_insert_mutator(out_buf, &out_len, enum_iter, map);
          }
          case 1: {
            out_buf = enum_delete_mutator(out_buf, &out_len, enum_iter, map);
          }
          case 2: {
            out_buf = enum_exchange_mutator(out_buf, &out_len, enum_iter, map);
          }
        }
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        if (out_len < len) {
          out_buf = ck_realloc(out_buf, len);
        }
        out_len = len;
        memcpy(out_buf, buf, len);
      }
    }
    enum_iter = enum_iter->next;
  }

  /*mutation length*/
  length_iter = track->lengths;
  while (length_iter != NULL) {
    uint32_t meta_len, payload_len;
    uint32_t start;
    meta_len = payload_len = 0;

    if (length_iter->start > out_len || length_iter->end > out_len ||
        length_iter->target_start > out_len ||
        length_iter->target_end > out_len) {
      length_iter = length_iter->next;
      continue;
    }
    meta_len = length_iter->end - length_iter->start;
    payload_len = length_iter->target_end - length_iter->target_start;
    if (meta_len != 1 && meta_len != 2 && meta_len != 4) {
      length_iter = length_iter->next;
      continue;
    }
    if (length_iter->start + meta_len > out_len) {
      length_iter = length_iter->next;
      continue;
    }
    /* add to length field */
    for (i = 0; i <= 36; i += 2) {
      if (i >= out_len) {
        break;
      }
      number_add(out_buf, length_iter->start, meta_len, i);
      start = UR(out_len - i);
      /* new testcase */
      out_buf =
          copy_and_insert(out_buf, &out_len, length_iter->target_end, start, i);

      /* save testcase if interesting */
      if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
        goto exit_describing_aware_stage;

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = ck_realloc(out_buf, len);
      }
      out_len = len;
      memcpy(out_buf, buf, len);
      stage_max++;
    }

    /* delete from length field */
    for (i = 2; i < payload_len; i += 2) {
      number_add(out_buf, length_iter->start, meta_len, -i);
      /* new testcase */
      out_buf = delete_data(out_buf, &out_len, length_iter->target_start, i);

      /* save testcase if interesting */
      if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
        goto exit_describing_aware_stage;

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = ck_realloc(out_buf, len);
      }
      out_len = len;
      memcpy(out_buf, buf, len);
      stage_max++;
    }

    /* set interesting value */
    u32 index = length_iter->start;
    if (meta_len == 1) {
      u8 orig = out_buf[index];
      for (i = 0; i < sizeof(interesting_8); i++) {
        out_buf[index] = interesting_8[i];
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
      }
      out_buf[index] = orig;
    } else if (meta_len == 2) {
      u16 orig = *(u16 *)(out_buf + index);
      for (i = 0; i < sizeof(interesting_16) / 2; i++) {
        *(u16 *)(out_buf + index) = interesting_16[i];
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
        *(u16 *)(out_buf + index) = SWAP16(interesting_16[i]);
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
      }
      *(u16 *)(out_buf + index) = orig;
    } else if (meta_len == 4) {
      u32 orig = *(u32 *)(out_buf + index);
      for (i = 0; i < sizeof(interesting_32) / 4; i++) {
        *(u32 *)(out_buf + index) = interesting_32[i];
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
        *(u32 *)(out_buf + index) = SWAP32(interesting_32[i]);
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
      }
      *(u32 *)(out_buf + index) = orig;
    }
    length_iter = length_iter->next;
  }

  /*mutation offset*/
  offset_iter = track->offsets;
  while (offset_iter != NULL) {
    u32 meta_length, payload_length;
    if (offset_iter->start > out_len || offset_iter->end > out_len ||
        offset_iter->target_start > out_len ||
        offset_iter->target_end > out_len) {
      offset_iter = offset_iter->next;
      continue;
    }
    meta_length = offset_iter->end - offset_iter->start;
    if (meta_length != 1 && meta_length != 2 && meta_length != 4) {
      offset_iter = offset_iter->next;
      continue;
    }
    if (offset_iter->start + meta_length > out_len) {
      offset_iter = offset_iter->next;
      continue;
    }
    payload_length = offset_iter->target_end - offset_iter->target_start;
    /* add to offset field */
    for (i = 1; i < 36; i++) {
      if (i > out_len) {
        break;
      }
      number_add(out_buf, offset_iter->start, meta_length, i);
      /* new testcase */
      out_buf = copy_and_insert(out_buf, &out_len, offset_iter->start,
                                UR(out_len - i), i);

      /* save testcase if interesting */
      if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
        goto exit_describing_aware_stage;

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = ck_realloc(out_buf, len);
      }
      out_len = len;
      memcpy(out_buf, buf, len);
      stage_max++;
    }

    /* delete from offset field */
    for (i = 2; i < payload_length; i += 2) {
      number_add(out_buf, offset_iter->start, meta_length, -i);
      /* new testcase */
      out_buf = delete_data(out_buf, &out_len, offset_iter->target_start, i);

      /* save testcase if interesting */
      if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
        goto exit_describing_aware_stage;

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = ck_realloc(out_buf, len);
      }
      out_len = len;
      memcpy(out_buf, buf, len);
      stage_max++;
    }

    /* set interesting value */
    u32 index = offset_iter->start;
    if (meta_length == 1) {
      u8 orig = out_buf[index];
      for (i = 0; i < sizeof(interesting_8); i++) {
        out_buf[index] = interesting_8[i];
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
      }
      out_buf[index] = orig;
    } else if (meta_length == 2) {
      u16 orig = *(u16 *)(out_buf + index);
      for (i = 0; i < sizeof(interesting_16) / 2; i++) {
        *(u16 *)(out_buf + index) = interesting_16[i];
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
        *(u16 *)(out_buf + index) = SWAP16(interesting_16[i]);
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
      }
      *(u16 *)(out_buf + index) = orig;
    } else if (meta_length == 4) {
      u32 orig = *(u32 *)(out_buf + index);
      for (i = 0; i < sizeof(interesting_32) / 4; i++) {
        *(u32 *)(out_buf + index) = interesting_32[i];
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
        *(u32 *)(out_buf + index) = SWAP32(interesting_32[i]);
        if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
          goto exit_describing_aware_stage;
        stage_max++;
      }
      *(u32 *)(out_buf + index) = orig;
    }

    offset_iter = offset_iter->next;
  }

  /*mutation constraint*/
  cons_iter = track->constraints;
  while (cons_iter != NULL) {
    cons_iter = cons_iter->next;
  }

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_STRUCT_AWARE] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_STRUCT_AWARE] += stage_max;

exit_describing_aware_stage:
  ck_free(out_buf);
  free(map);
}

void struct_havoc_stage(char **argv, u8 *buf, u32 len, Chunk *tree,
                        Track *track) {
  u8 **all_chunks;
  u32 chunk_num = 0, out_len, splice_cycle = 0;
  u32 stage_max, stage_cur, i, perf_score = 100, orig_perf;
  u64 orig_hit_cnt, new_hit_cnt, struct_havoc_queued;
  u8 *out_buf;
  Enum *enum_field = NULL;
  out_len = len;
  out_buf = ck_alloc(len);
  memcpy(out_buf, buf, len);
  HashMap map = createHashMap(NULL, NULL);
  tree_add_map(tree->child, map);
  all_chunks = ck_alloc(map->size * sizeof(u8 *));
  HashMapIterator map_iter = createHashMapIterator(map);
  while (hasNextHashMapIterator(map_iter)) {
    map_iter = nextHashMapIterator(map_iter);
    all_chunks[chunk_num] = map_iter->entry->key;
    chunk_num++;
  }

  orig_perf = perf_score = calculate_score(queue_cur);

struct_havoc_stage:

  if (!splice_cycle) {
    stage_name = "struct_havoc";
    stage_short = "chunkFuzzer3";
    stage_max = HAVOC_CYCLES * perf_score / havoc_div / 100;

  } else {
    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "struct_splice %u", splice_cycle);
    stage_name = tmp;
    stage_short = "struct_splice";
    stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;
  }

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;
  stage_cur = 0;

  orig_hit_cnt = queued_paths + unique_crashes;
  struct_havoc_queued = queued_paths;
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
      u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));
      for (i = 0; i < use_stacking; i++) {
      u32 num;
      num = UR(11 + ((track == NULL) ? 0 : 2));
      //SAYF("#Before mutate num is %d, out_len is %d\n", num, out_len);
      switch (num) {
        case 0: {
          out_buf = flip_bit_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 1: {
          out_buf = set_byte_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 2: {
          out_buf = set_word_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 3: {
          out_buf = set_dword_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 4: {
          out_buf = sub_byte_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 5: {
          out_buf = add_byte_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 6: {
          out_buf = sub_word_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 7: {
          out_buf = add_word_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 8: {
          out_buf = sub_dword_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 9: {
          out_buf = add_dword_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 10: {
          out_buf = random_set_byte_mutator(out_buf, out_len, map, all_chunks, chunk_num);
          break;
        }
        case 11: {
          enum_field = get_random_enum(track->enums);
          out_buf = overwrite_with_enum_mutator(out_buf, &out_len, enum_field, all_chunks, chunk_num);
          break;
        }
        case 12: {
          enum_field = get_random_enum(track->enums);
          out_buf = insert_with_enum_mutator(out_buf, &out_len, enum_field, all_chunks, chunk_num);
          break;
        }
      }
      //SAYF("#After mutate num is %d, out_len is %d\n", num, out_len);
    }

    if (common_fuzz_stuff(argv, out_buf, out_len, tree, track))
      goto exit_struct_havoc_stage;

    if (out_len < len) {
      out_buf = ck_realloc(out_buf, len);
    }
    out_len = len;
    memcpy(out_buf, buf, len);

    if (queued_paths != struct_havoc_queued) {
      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max *= 2;
        perf_score *= 2;
      }

      struct_havoc_queued = queued_paths;
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;
  if(!splice_cycle) {
    stage_finds[STAGE_STRUCT_HAVOC] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_STRUCT_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_STRUCT_SPLICE] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_STRUCT_SPLICE] += stage_max;
  }

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES && queued_paths > 1 &&
      queue_cur->len > 1) {
    struct queue_entry *target;
    u32 tid, split_at;
    u8 *new_buf;
    s32 f_diff, l_diff;

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do {
      tid = UR(queued_paths);
    } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100) {
      target = target->next_100;
      tid -= 100;
    }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    u32 fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(out_buf, new_buf, MIN(out_len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    out_len = target->len;
    memcpy(new_buf, out_buf, split_at);

    ck_free(out_buf);
    out_buf = ck_alloc(out_len);
    memcpy(out_buf, new_buf, out_len);
    ck_free(new_buf);
    goto struct_havoc_stage;
  }

exit_struct_havoc_stage:

  freeHashMapIterator(&map_iter);
  map->clear(map);
  free(map);
  ck_free(all_chunks);
  ck_free(out_buf);
}

u8* insert_chunk_mutator(u8 *buf, u32 *len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  u32 index1, index2;
  index1 = UR(chunk_num);
  index2 = UR(chunk_num);
  buf = insert_chunk(buf, len, map, all_chunks[index1], all_chunks[index2], UR(2));
  return buf;
}

u8* delete_chunk_mutator(u8 *buf, u32 *len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  u32 index;
  index = UR(chunk_num);
  buf = delete_chunk(buf, len, map, all_chunks[index]);
  return buf;
}

u8* exchange_chunk_mutator(u8 *buf, u32 *len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunks[2];
  chunks[0] = NULL;
  chunks[1] = NULL;
  get_exchange_chunks(chunk_num, all_chunks, map, chunks);
  buf = exchange_chunk(buf, *len, chunks[0], chunks[1]);
  return buf;
}

u8* enum_mutator(u8 *buf, u32 len, Enum *enum_field, u32 candi_index) {
  if (enum_field == NULL) {
    return buf;
  }
  if (enum_field->start > len || enum_field->end > len) {
    return buf;
  }
  u32 chunk_len = enum_field->end - enum_field->start;
  u32 candi_len = 0;
  u8 *candi_str = parse_candidate(enum_field->candidates[candi_index], &candi_len);
  u32 copy_len = chunk_len > candi_len ? candi_len : chunk_len;
  memcpy(buf + enum_field->start, candi_str, copy_len);
  ck_free(candi_str);
  return buf;
}

u8* increase_len_mutator(u8* buf, u32 len, Length *len_field, u32 num) {
  u32 set_start, set_len;
  if (len_field == NULL || len_field->start > len || len_field->end > len) {
    return buf;
  }
  set_start = len_field->start;
  set_len = len_field->end - len_field->start;
  // int32_t num = 1 + UR(ARITH_MAX);
  number_add(buf, set_start, set_len, num);
  return buf;
}

u8* decrease_len_mutator(u8* buf, u32 len, Length *len_field, u32 num) {
  u32 set_start, set_len;
  if (len_field == NULL || len_field->start > len || len_field->end > len) {
    return buf;
  }
  set_start = len_field->start;
  set_len = len_field->end - len_field->start;
  // int32_t num = 1 + UR(ARITH_MAX);
  number_subtract(buf, set_start, set_len, num);
  return buf;
}

u8* set_len_mutator(u8* buf, u32 len, Length *len_field, u32 interest_index) {
  u32 set_start, set_len;
  if (len_field == NULL || len_field->start > len || len_field->end > len) {
    return buf;
  }
  set_start = len_field->start;
  set_len = len_field->end - len_field->start;
  number_set_interesting(buf, set_start, set_len, interest_index);
  return buf;
}

u8* insert_len_payload_mutator(u8* buf, u32 *len, Length *len_field) {
  u32 clone_from, clone_to, clone_len, payload_start, payload_end;
  u8 acturally_clone = UR(4);
  u8 *new_buf;
  if (len_field == NULL || len_field->target_start > *len ||
      len_field->target_end > *len) {
    return buf;
  }
  payload_start = len_field->target_start;
  payload_end = len_field->target_end;
  if (acturally_clone) {
    clone_len = choose_block_len(*len);
    clone_from = UR(*len - clone_len + 1);
  } else {
    clone_len = choose_block_len(HAVOC_BLK_XL);
    clone_from = 0;
  }
  clone_to = payload_start + UR(payload_end - payload_start);
  new_buf = ck_alloc(*len + clone_len);

  /* Head */
  memcpy(new_buf, buf, clone_to);

  /* Inserted part */
  if (acturally_clone) {
    memcpy(new_buf + clone_to, buf + clone_from, clone_len);
  } else {
    memset(new_buf + clone_to, UR(2) ? UR(256) : buf[UR(*len)],
            clone_len);
  }

  /* Tail */
  memcpy(new_buf + clone_to + clone_len, buf + clone_to,
          *len - clone_to);
  ck_free(buf);
  buf = new_buf;
  *len += clone_len;

  buf = increase_len_mutator(buf, *len, len_field, clone_len);

  return buf;
}

u8* delete_len_payload_mutator(u8* buf, u32 *len, Length *len_field) {
  uint32_t del_from, del_len, payload_start, payload_end;
  if (*len < 2) {
    return buf;
  }
  if (len_field == NULL || len_field->target_start > *len ||
      len_field->target_end > *len) {
    return buf;
  }
  payload_start = len_field->target_start;
  payload_end = len_field->target_end;

  if (payload_end - payload_start < 2) {
    return buf;
  }
  del_len = choose_block_len(payload_end - payload_start - 1);
  del_from = payload_start + UR(payload_end - payload_start - del_len);
  memmove(buf + del_from, buf + del_from + del_len,
          *len - del_from - del_len);
  *len -= del_len;

  buf = decrease_len_mutator(buf, *len, len_field, del_len);

  return buf;
}

u8* increase_offset_mutator(u8* buf, u32 len, Offset *offset_field, u32 num) {
  u32 set_start, set_len;
  if (offset_field == NULL || offset_field->start > len || offset_field->end > len) {
    return buf;
  }
  set_start = offset_field->start;
  set_len = offset_field->end - offset_field->start;
  // int32_t num = 1 + UR(ARITH_MAX);
  number_add(buf, set_start, set_len, num);
  return buf;
}

u8* decrease_offset_mutator(u8* buf, u32 len, Offset *offset_field, u32 num) {
  u32 set_start, set_len;
  if (offset_field == NULL || offset_field->start > len || offset_field->end > len) {
    return buf;
  }
  set_start = offset_field->start;
  set_len = offset_field->end - offset_field->start;
  // int32_t num = 1 + UR(ARITH_MAX);
  number_subtract(buf, set_start, set_len, num);
  return buf;
}

u8* set_offset_mutator(u8* buf, u32 len, Offset *offset_field, u32 interest_index) {
  u32 set_start, set_len;
  if (offset_field == NULL || offset_field->start > len || offset_field->end > len) {
    return buf;
  }
  set_start = offset_field->start;
  set_len = offset_field->end - offset_field->start;
  number_set_interesting(buf, set_start, set_len, interest_index);
  return buf;
}

u8* insert_offset_payload_mutator(u8* buf, u32 *len, Offset *offset_field) {
  u32 clone_from, clone_to, clone_len, payload_start, payload_end;
  u8 acturally_clone = UR(4);
  u8 *new_buf;
  if (offset_field == NULL || offset_field->target_start > *len ||
      offset_field->target_end > *len) {
    return buf;
  }
  payload_start = offset_field->target_start;
  payload_end = offset_field->target_end;
  if (acturally_clone) {
    clone_len = choose_block_len(*len);
    clone_from = UR(*len - clone_len + 1);
  } else {
    clone_len = choose_block_len(HAVOC_BLK_XL);
    clone_from = 0;
  }
  clone_to = payload_start + UR(payload_end - payload_start);
  new_buf = ck_alloc(*len + clone_len);

  /* Head */
  memcpy(new_buf, buf, clone_to);

  /* Inserted part */
  if (acturally_clone) {
    memcpy(new_buf + clone_to, buf + clone_from, clone_len);
  } else {
    memset(new_buf + clone_to, UR(2) ? UR(256) : buf[UR(*len)],
            clone_len);
  }

  /* Tail */
  memcpy(new_buf + clone_to + clone_len, buf + clone_to,
          *len - clone_to);
  ck_free(buf);
  buf = new_buf;
  *len += clone_len;

  buf = increase_offset_mutator(buf, *len, offset_field, clone_len);

  return buf;
}

u8* delete_offset_payload_mutator(u8* buf, u32 *len, Offset *offset_field) {
 uint32_t del_from, del_len, payload_start, payload_end;
  if (*len < 2) {
    return buf;
  }
  if (offset_field == NULL || offset_field->target_start > *len ||
      offset_field->target_end > *len) {
    return buf;
  }
  payload_start = offset_field->target_start;
  payload_end = offset_field->target_end;

  if (payload_end - payload_start < 2) {
    return buf;
  }
  del_len = choose_block_len(payload_end - payload_start - 1);
  del_from = payload_start + UR(payload_end - payload_start - del_len);
  memmove(buf + del_from, buf + del_from + del_len,
          *len - del_from - del_len);
  *len -= del_len;

  buf = decrease_offset_mutator(buf, *len, offset_field, del_len);

  return buf;
}

u8* enum_insert_mutator(u8* buf, u32 *len, Enum *enum_field, HashMap map) {
  if(enum_field == NULL) {
    return buf;
  }
  Chunk *chunk = map->get(map, enum_field->id);
  if(chunk == NULL) {
    return buf;
  }
  Chunk *copy_chunk = chunk->parent;
  if(copy_chunk == NULL || copy_chunk->parent == NULL) {
    return buf;
  }
  Chunk *insert_chunk = get_random_chunk(copy_chunk->parent);
  if (copy_chunk->start > *len || copy_chunk->end > *len || insert_chunk->end > *len) {
    return buf;
  }
  buf = copy_and_insert(buf, len, insert_chunk->end, copy_chunk->start, copy_chunk->end - copy_chunk->start);
  buf = enum_mutator(buf, *len, enum_field, UR(enum_field->cans_num));
  return buf;
}

u8* enum_delete_mutator(u8* buf, u32 *len, Enum *enum_field, HashMap map) {
  if(enum_field == NULL) {
    return buf;
  }
  Chunk *chunk = map->get(map, enum_field->id);
  if(chunk == NULL) {
    return buf;
  }
  Chunk *delete_chunk = chunk->parent;
  if(delete_chunk == NULL || delete_chunk->parent == NULL) {
    return buf;
  }
  if (delete_chunk->start > *len || delete_chunk->end > *len) {
    return buf;
  }
  if(delete_chunk->end - delete_chunk->start >= *len) {
    return buf;
  } 
  return delete_data(buf, len, delete_chunk->start, delete_chunk->end - delete_chunk->start);
}

u8* enum_exchange_mutator(u8* buf, u32 *len, Enum *enum_field, HashMap map) {
  if(enum_field == NULL) {
    return buf;
  }
  Chunk *chunk = map->get(map, enum_field->id);
  if(chunk == NULL) {
    return buf;
  }
  Chunk *chunk1 = chunk->parent;
  if(chunk1 == NULL || chunk1->parent == NULL) {
    return buf;
  }
  Chunk *chunk2 = get_random_chunk(chunk1->parent->child);
  if (chunk_overleap(chunk1, chunk2)) {
    return buf;
  }
  if (strcmp(chunk1->id, chunk2->id) == 0) {
    return buf;
  }
  Chunk *temp;
  if (chunk1->end >= chunk2->end) {
    temp = chunk1;
    chunk1 = chunk2;
    chunk2 = temp;
  }
  buf = exchange_chunk(buf, *len, chunk1, chunk2);
  buf = enum_mutator(buf, *len, enum_field, UR(enum_field->cans_num));
  return buf;
}

u8* high_order_structure_mutator(u8* buf, u32 *len, HashMap map, Chunk *tree) {
  if(tree == NULL) {
    return buf;
  }
  u32 level = UR(3);
  Chunk *root = NULL;
  if(level == 0) {
    root = tree->child;
  } else if(level == 1) {
    root = get_random_chunk(tree->child);
    if(root) {
      root = root->child;
    }
  } else if(level == 2) {
    root = get_random_chunk(tree->child);
    if(root) {
      root = get_random_chunk(root->child);
      if(root) {
        root = root->child;
      }
    }
  }
  if(root == NULL || root->next == NULL) {
    return buf;
  }
  switch (UR(3)) {
    case 0: {
      buf = insert_chunk(buf, len, map, get_random_chunk(root)->id, get_random_chunk(root)->id, UR(2));
      break;
    }
    case 1: {
      Chunk *delete_chunk = get_random_chunk(root);
      if (delete_chunk->start > *len || delete_chunk->end > *len) {
        return buf;
      }
      if(delete_chunk->end - delete_chunk->start == *len) {
        return buf;
      }
      buf = delete_data(buf, len, delete_chunk->start, delete_chunk->end - delete_chunk->start);
      break;
    }
    case 2: {
      Chunk *chunk = get_random_chunk(root->next);
      if(chunk == NULL) {
        return buf;
      }
      if(chunk_overleap(root, chunk)) {
        return buf;
      }
      buf = exchange_chunk(buf, *len, root, chunk);
      break;
    }
  }
  return buf;
}

u8* multiple_enum_mutator(u8* buf, u32 *len, Enum *enum_field, HashMap map, Track *track) {
  // if(enum_field == NULL) {
  //   return buf;
  // }
  // Chunk *item = map->get(map, enum_field->id);
  // if(item == NULL) {
  //   return buf;
  // }
  // Chunk *chunk = item->parent;
  // if(chunk == NULL) {
  //   return buf;
  // }
  // HashMap enum_map = createHashMap(NULL, NULL);
  // while(chunk) {
  //   Chunk *child = chunk->child;
  //   while(child) {
  //     if(enum_map->get(enum_map, child->id)) {
  //       Enum *enum_field = enum_map->get(enum_map, child->id);
  //       if(UR(2)) {
  //         buf = enum_mutator(buf, *len, enum_field, UR(enum_field->cans_num));
  //       }
  //     }
  //     child = child->next;
  //   }
  //   chunk = chunk->next;
  // }
  return buf;
}

u8* flip_bit_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  #define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || chunk->start >= len) {
    return buf;
  }else {
    FLIP_BIT(buf, chunk->start << 3);
  }
  return buf;
}

u8* set_byte_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || chunk->start >= len) {
    return buf;
  }else {
    buf[chunk->start] = interesting_8[UR(sizeof(interesting_8))];
  }
  return buf;
}

u8* set_word_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || len < 2 ||chunk->start >= len - 1) {
    return buf;
  }else {
    if (UR(2)) {
      *(u16*)(buf + chunk->start) = interesting_16[UR(sizeof(interesting_16) >> 1)];
    } else {
      *(u16*)(buf + chunk->start) = SWAP16(interesting_16[UR(sizeof(interesting_16) >> 1)]);
    }
  }
  return buf;
}


u8* set_dword_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || len < 4 ||chunk->start >= len - 3) {
    return buf;
  }else {
    if (UR(2)) {
      *(u32*)(buf + chunk->start) = interesting_32[UR(sizeof(interesting_32) >> 2)];
    } else {
      *(u32*)(buf + chunk->start) = SWAP32(interesting_32[UR(sizeof(interesting_32) >> 2)]);
    }
  }
  return buf;
}

u8* sub_byte_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || chunk->start >= len) {
    return buf;
  }else {
    buf[chunk->start] -= 1 + UR(ARITH_MAX);
  }
  return buf;
}

u8* add_byte_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || chunk->start >= len) {
    return buf;
  }else {
    buf[chunk->start] += 1 + UR(ARITH_MAX);
  }
  return buf;
}

u8* sub_word_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || len < 2 ||chunk->start >= len - 1) {
    return buf;
  }else {
    if (UR(2)) {
      *(u16*)(buf + chunk->start) -= 1 + UR(ARITH_MAX);
    } else {
      u16 num = 1 + UR(ARITH_MAX);
      *(u16*)(buf + chunk->start) = SWAP16(SWAP16(*(u16*)(buf + chunk->start)) - num);
    }
  }
  return buf;
}

u8* add_word_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || len < 2 ||chunk->start >= len - 1) {
    return buf;
  }else {
    if (UR(2)) {
      *(u16*)(buf + chunk->start) += 1 + UR(ARITH_MAX);
    } else {
      u16 num = 1 + UR(ARITH_MAX);
      *(u16*)(buf + chunk->start) = SWAP16(SWAP16(*(u16*)(buf + chunk->start)) + num);
    }
  }
  return buf;
}

u8* sub_dword_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || len < 4 ||chunk->start >= len - 3) {
    return buf;
  }else {
    if (UR(2)) {
      *(u32*)(buf + chunk->start) -= 1 + UR(ARITH_MAX);
    } else {
      u32 num = 1 + UR(ARITH_MAX);
      *(u32*)(buf + chunk->start) = SWAP32(SWAP32(*(u32*)(buf + chunk->start)) - num);
    }
  }
  return buf;
}

u8* add_dword_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  if(chunk_num == 0) {
    return buf;
  }
  Chunk *chunk = map->get(map, all_chunks[UR(chunk_num)]);
  if(chunk == NULL || len < 4 ||chunk->start >= len - 3) {
    return buf;
  }else {
    if (UR(2)) {
      *(u32*)(buf + chunk->start) += 1 + UR(ARITH_MAX);
    } else {
      u32 num = 1 + UR(ARITH_MAX);
      *(u32*)(buf + chunk->start) = SWAP32(SWAP32(*(u32*)(buf + chunk->start)) + num);
    }
  }
  return buf;
}

u8* random_set_byte_mutator(u8* buf, u32 len, HashMap map, u8 **all_chunks, u32 chunk_num) {
  buf[UR(len)] ^= 1 + UR(255);
  return buf;
}

u8* overwrite_with_enum_mutator(u8* buf, u32 *len, Enum *enum_field, u8 **all_chunks, u32 chunk_num) {
  if(enum_field == NULL || enum_field->start > *len || enum_field->cans_num == 0) {
    return buf;
  }
  u32 insert_at;
  u32 chunk_len = enum_field->end - enum_field->start;
  u32 candi_len = 0;
  u8 *candi_str = parse_candidate(enum_field->candidates[UR(enum_field->cans_num)], &candi_len);
  u32 copy_len = chunk_len > candi_len ? candi_len : chunk_len;
  if(*len <= copy_len) {
    return buf;
  }
  insert_at = UR(*len - copy_len + 1);
  memcpy(buf + insert_at, candi_str, copy_len);
  return buf;
}

u8* insert_with_enum_mutator(u8* buf, u32 *len, Enum *enum_field, u8 **all_chunks, u32 chunk_num) {
  if(enum_field == NULL || enum_field->start > *len || enum_field->cans_num == 0) {
    return buf;
  }
  u8* new_buf;
  u32 insert_at;
  u32 chunk_len = enum_field->end - enum_field->start;
  u32 candi_len = 0;
  u8 *candi_str = parse_candidate(enum_field->candidates[UR(enum_field->cans_num)], &candi_len);
  u32 copy_len = chunk_len > candi_len ? candi_len : chunk_len;
  insert_at = UR(*len+ 1);
  new_buf = ck_alloc_nozero(*len + copy_len);

  /* Head */
  memcpy(new_buf, buf, insert_at);

  /* Inserted part */
  memcpy(new_buf + insert_at, candi_str, copy_len);

  memcpy(new_buf + insert_at + copy_len, buf + insert_at, *len - insert_at);

  ck_free(buf);
  *len += copy_len;
  return new_buf;
}