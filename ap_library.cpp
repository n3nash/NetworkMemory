#include "ap_code.h"
#include<math.h>
#include<stdint.h>
#include<string.h>
#include<stdlib.h>

int redundancy_regular=0,redundancy_feedback=0;

static int compare_key(void *one, void *two){
    int i;
	if(!strcmp((char*)one,(char*)two))
		return 0;
    return 1;
}

map_handle* allocate_map(void) {
    map_handle *map;
    map = (map_handle*) malloc(sizeof(struct map));
    if (map == NULL) {
        //printlog(LOG_WARN, "allocate_map failed.");
        return NULL;
    }
    //memset(map,0,sizeof(struct map*));
    map->size = 0;
    return(map);
}


int hash_fn(void* in) {
    //static int a;
	static uint32_t a;
    a = *((int*) in);

    a = (a+0x7ed55d16) + (a << 12);
    a = (a^0xc761c23c) ^ (a >> 19);
    a = (a+0x165667b1) + (a << 5);
    a = (a+0xd3a2646c) ^ (a << 9);
    a = (a+0xfd7046c5) + (a << 3);
    a = (a^0xb55a4f09) ^ (a >> 16);

    return a;
}

int internal_search(map_handle *map, void *key ,void *value , int x){
    uint32_t index;
    struct map_entry *nxt_node;

    index = hash_fn(key) & (GENERIC_HASH_SIZE - 1);

	if(map->table[index]==NULL)
		return NULL;

    nxt_node = (struct map_entry*) map->table[index];

    while(nxt_node){
        if (compare_key(nxt_node->key,key)){
	//	printf("found one\n");
            return(*(int*)value);
        }
       
        nxt_node = nxt_node->nxt;
    }
	//printf("here means nul\n");
    return(0);

}




int map_insert_regular_or_feedback(map_handle *map, void *key,void *value,int map_id)
{

    struct map_entry *hash_node,*add_this_node;
    uint32_t index,hash;

//me is hash_node
//add_this_node is second.

    index = hash_fn(key) & (GENERIC_HASH_SIZE - 1);//jhash(key,keylen,util_salt) & (GENERIC_HASH_SIZE - 1);
    hash = index;

        hash_node = (struct map_entry*) malloc(sizeof(struct map_entry));
        add_this_node = (struct map_entry*) malloc(sizeof(struct map_entry));
                if(map->table[hash]!=NULL)
                        {
                                hash_node = (struct map_entry*)map->table[hash];
                                //printf("check for list\n");
                        if(hash_node!=NULL){
                                while(hash_node->nxt!=NULL)
                        {

                        if (compare_key(hash_node->key,key)){
				  if ( map_id == 1){
                                  redundancy_regular += (int)value;
				  return redundancy_regular;}
				  if( map_id == 2){
				  redundancy_feedback += (int)value;
				  return (redundancy_feedback);}
                                         }
                                //printf("%d",*(int*)me->value);
                                hash_node = hash_node->nxt;
                                //printf("after one move\n");
                        }}
                        add_this_node->value = value;
                        add_this_node->nxt = hash_node;
                        hash_node->nxt = NULL;
                        map->table[hash] = add_this_node;
                        map->size++;
                        //printf("found nul\n");
                                }
                else
                {

                hash_node->key = key;
                hash_node->value = value;
                hash_node->nxt = NULL;
                map->table[hash] = hash_node;

                map->size++;}

                //flag = 1;
    /* now pme is at the end of the list on that index */
    if (hash_node == NULL) {
        //printf("how come\n");
        //printlog(LOG_WARN, "util.c: insert failed, malloc failure");
        return 0;
    }
        //printf("exiting");
    return (0);


}


