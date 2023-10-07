#ifndef __HASHMAP_H__
#define __HASHMAP_H__

#include <stdint.h>
#include "chunk.h"

typedef struct entry {
	uint8_t *key;
	Chunk *value;
	struct entry * next;
}*Entry;

#define newEntry() (Entry)malloc(sizeof(struct entry))
#define newEntryList(length) (Entry)malloc(length * sizeof(struct entry))

enum _Boolean { True = 1, False = 0 };
typedef enum _Boolean Boolean;

// 哈希结构
typedef struct hashMap *HashMap;

#define newHashMap() (HashMap)malloc(sizeof(struct hashMap))

// 哈希函数类型
typedef uint32_t(*HashCode)(HashMap, uint8_t *key);

// 判等函数类型
typedef Boolean(*Equal)(uint8_t *key1, uint8_t *key2);

// 添加键函数类型
typedef void(*Put)(HashMap hashMap, uint8_t *key, Chunk *value);

// 获取键对应值的函数类型
typedef Chunk *(*Get)(HashMap hashMap, uint8_t *key);

// 删除键的函数类型
typedef uint8_t *(*Remove)(HashMap hashMap, uint8_t *key);

// 清空Map的函数类型
typedef void(*Clear)(HashMap hashMap);

// 判断键值是否存在的函数类型
typedef Boolean(*Exists)(HashMap hashMap, uint8_t *key);

typedef struct hashMap {
	uint32_t size;			// 当前大小
	uint32_t listSize;		// 有效空间大小
	HashCode hashCode;	// 哈希函数
	Equal equal;		// 判等函数
	Entry list;			// 存储区域
	Put put;			// 添加键的函数
	Get get;			// 获取键对应值的函数
	Remove remove;		// 删除键
	Clear clear;		// 清空Map
	Exists exists;		// 判断键是否存在
	Boolean autoAssign;	// 设定是否根据当前数据量动态调整内存大小，默认开启
}*HashMap;

// 迭代器结构
typedef struct hashMapIterator {
	Entry entry;	// 迭代器当前指向
	uint32_t count;		// 迭代次数
	uint32_t hashCode;	// 键值对的哈希值
	HashMap hashMap;
}*HashMapIterator;

#define newHashMapIterator() (HashMapIterator)malloc(sizeof(struct hashMapIterator))

// 默认哈希函数
uint32_t defaultHashCode(HashMap hashMap, uint8_t *key);

// 默认判断键值是否相等
Boolean defaultEqual(uint8_t *key1, uint8_t *key2);

// 默认添加键值对
void defaultPut(HashMap hashMap, uint8_t *key, Chunk *value);

// 默认获取键对应值
Chunk *defaultGet(HashMap hashMap, uint8_t *key);

// 默认删除键
uint8_t *defaultRemove(HashMap hashMap, uint8_t *key);

// 默认判断键是否存在
Boolean defaultExists(HashMap hashMap, uint8_t *key);

// 默认清空Map
void defaultClear(HashMap hashMap);

// 重新构建
void resetHashMap(HashMap hashMap, uint32_t listSize);

// 创建一个哈希结构
HashMap createHashMap(HashCode hashCode, Equal equal);

// 创建哈希结构迭代器
HashMapIterator createHashMapIterator(HashMap hashMap);

// 迭代器是否有下一个
Boolean hasNextHashMapIterator(HashMapIterator iterator);

// 迭代到下一次
HashMapIterator nextHashMapIterator(HashMapIterator iterator);

// 释放迭代器内存
void freeHashMapIterator(HashMapIterator * iterator);

#endif // !__HASHMAP_H__