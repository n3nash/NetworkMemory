#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include<string.h>
#include<arpa/inet.h>

#ifndef _HASH_MAP_H_
#define _HASH_MAP_H_

#define GENERIC_HASH_SIZE 2<<15

/*struct connections
{
	char sourceIP[INET_ADDRSTRLEN];
	char destinationIP[INET_ADDRSTRLEN];
	uint16_t sourcePORT; 
	uint16_t destinationPORT;
	uint32_t cid;
	int size;
	struct connections *nxt;
	//struct DSforCalculation *datastructure; //think about it.
};*/


typedef struct connections connection_handle;


struct map{
    struct map_entry *table[GENERIC_HASH_SIZE];
    int size;
    //int arrayofconnectionrepetitions;
};

typedef struct map map_handle;

struct connlist
{
int cid;
struct connlist *next;
struct connlist *next_pointer_to_thisconn;
struct map_entry *pointer_to_hashnode;
};

struct map_entry {
    struct map_entry *nxt;
    void *key;
    void *value;
    struct connlist *conn_list;
};

map_handle* allocate_map(void);
int add_connection(char a[INET_ADDRSTRLEN],char b[INET_ADDRSTRLEN],int c,int d);
void* map_insert(map_handle *map, void *key, void *value,uint32_t current_connection_id,int pfile,int a,int pktn);

#endif
