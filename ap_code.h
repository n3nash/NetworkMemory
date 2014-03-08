#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include<string.h>
#include<arpa/inet.h>
#define GENERIC_HASH_SIZE 2<<15

struct map{
    struct map_entry *table[GENERIC_HASH_SIZE];
    int size;
};

struct map_entry {
    struct map_entry *nxt;
    void *key;
    void *value;
};

typedef struct map map_handle;

map_handle* allocate_map(void);

int internal_search(map_handle *map, void *key, void *value , int x);
//struct map_entry*

int map_insert_regular_or_feedback(map_handle *map_regular, void *key,void *value,int keylen);

int map_size(map_handle *map);
