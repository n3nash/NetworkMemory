#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "mobile_code.h"
#include<math.h>
#include<map>
#include<utility>
using namespace std;

uint32_t current_connection_id;
int newflag=0,flag_lib=0,redundancy=0,start_point_firsttime;
uint32_t cid=0,last=0;
long long int totalR;
int k=0,best_connection=0,j=0,previouspacket,present_connection_id,store_packetnumber,numberofhashes,number_of_hashes_traversed=0;
int feedback_cids=0,hash_number=0;

int done = 1;
int flag_test=1,found;
int connectionflag =1;

int array_if_ids[1000];
int first=0;

std::map<int , int>array_of_cids;

std::map<int , int>array_of_cids_per_packet;

std::map<int , struct connlist*> last_marker;
std::map<int , struct connlist*> start_marker;

struct connlist *start;

std::map<int, char *> hashes_array;

std::map<int , int> array_of_best_cids;

std::map<int , struct connlist*> current_marker;

//std::map<struct map_entry*,int> unique_hashes_seen;

std::map <char *,int > unique_hashes_seen;

std::map<int , int> check_for_unique_cids;
std::map<char*,char*> store_mapping;
std::map<char* ,int> connection_str;
struct connlist *counter;



struct
{
char sourceip[INET_ADDRSTRLEN];
char destip[INET_ADDRSTRLEN];
uint16_t sport;
uint16_t dport;

}typedef node;

//typedef struct node node;

struct Comparer
	: public std::binary_function<node, node, bool>
{
};
    const bool operator < (const node & Left, const node & Right)
    {
 //    return ((Left.sport!=Right.sport) || (Right.dport!=Left.dport) || (strncmp((Right.sourceip),(Left.sourceip), INET_ADDRSTRLEN)) || (strncmp((Right.destip),(Left.destip),INET_ADDRSTRLEN)));

// comparison logic goes here
        int cmp_srcip = strcmp(Left.sourceip, Right.sourceip);
        int cmp_destip = strcmp(Left.destip, Right.destip); 
        if (cmp_srcip < 0)
            return true;
        else if (cmp_srcip == 0)
            if (cmp_destip < 0)
                return true;
            else if (cmp_destip == 0)
                if (Left.sport < Right.sport)
                    return true;
                else if (Left.sport == Right.sport)
                    if (Left.dport < Right.dport)
                        return true;

        return false;
    }

std::map<node,int> mymap;

static int compare_key(void *one, void *two){
    int i;
	if(strcmp((char*)one,(char*)two))
		return 0;
        //if((*(int*)one) != (*(int*)two))//{
           // return 0;
    return 1;
}

//calculates the hash index.
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



int numdigits(int n)
{
return log10(n) + 1;
}


void init_hashing(void){
  //  util_salt = getpid() ^ time(NULL); // same as ulogd_drl
}

/* some stupid generic hash function things */
/* just return a map_handle */
map_handle* allocate_map(void) {
    map_handle *map_mobile;
    map_mobile = (map_handle*) malloc(sizeof(map_handle));
    if (map_mobile == NULL) {
        //printlog(LOG_WARN, "allocate_map failed.");
        return NULL;
    }
    //memset(map,0,sizeof(struct map*));
    //map->iterator = map->table[0];
    map_mobile->size = 0;
    return(map_mobile);
}


connection_handle *start_node;
//createa and add connections
/*connection_handle *make_connection(void)
{
	connection_handle *newconnection = (connection_handle*) malloc(sizeof(struct connect));	
	if(newconnection==NULL)
		return NULL;
	return(newconnection);
}*/


char* convert(int number)
{
char *converted;
converted = (char*)malloc(numdigits(current_connection_id)*sizeof(char)+2);
sprintf(converted,"%d",current_connection_id);
return converted;
}

int add_connection(char a[INET_ADDRSTRLEN],char b[INET_ADDRSTRLEN],int c,int d)
{
int length=0;
found=0;
last = cid;
node add;

strncpy(add.sourceip,a,INET_ADDRSTRLEN);
strncpy(add.destip,b,INET_ADDRSTRLEN);
//printf("passed is and copied is %s %s\n",a,add.sourceip);
add.sport = c;
add.dport = d;
//pair<map<node,int>::iterator,bool> ret;
std::pair<std::map<node,int>::iterator,bool> ret;
  // first insert function version (single parameter)
  //mymap.insert ( pair<node,int>(add,cid) );
  //mymap.insert ( pair<node,int>(add,last) )
 ret =  mymap.insert (pair<node,int>(add,last) );
	//return cid;
  //cout << ret.second;
  if (!ret.second)
  {
	return ret.first->second;
   // cout << "element 'z' already existed";
   // cout << " with a value of " << ret.first->second << endl;
  }
	else{
		cid++;
		printf("cid is %d\n",cid);
		return last;

		}

//newconnection++;
//printf("value is %s\n",newconnection3->sourceIP);
}




//void store_mapping(char *hash,char *data);

void *map_insert(map_handle *map_mobile, void *key, void *value,uint32_t current_connection_id, int start_adv,int packetnumber,int last_hash) {
    struct map_entry *hash_node,*second;
    uint32_t index,hash;
	uint32_t current_id = current_connection_id;
             
	struct connlist *read,*read_feedback;
	struct connlist *connection = (struct connlist*)malloc(sizeof(struct connlist));
	struct connlist *past = (struct connlist*)malloc(sizeof(struct connlist));
    index = hash_fn((void*)key) & (GENERIC_HASH_SIZE - 1);//jhash(key,keylen,util_salt) & (GENERIC_HASH_SIZE - 1);
    hash = index;
	
	hash_node = (struct map_entry*) malloc(sizeof(struct map_entry));
	hash_node->conn_list = (struct connlist*)malloc(sizeof(struct connlist));
	second = (struct map_entry*) malloc(sizeof(struct map_entry));
	 second->conn_list = (struct connlist*)malloc(sizeof(struct connlist));
		if(map_mobile->table[hash]!=NULL)
			{
				hash_node = (struct map_entry*)map_mobile->table[hash];
				//printf("check for list\n");
			if(hash_node!=NULL){
				while(hash_node->nxt!=NULL)
                        {
	
			if (compare_key((void*)hash_node->key,(void*)key)){  // if the incoming hash found
      				  //printf("found one\n");
				  redundancy += *(int*)value;
				//hash_node->a[current_connection_id] += 1;
				read = (struct connlist*)hash_node->conn_list; //traverse the end of the connlist to add the new one(connection id)

				while(read->next!=NULL){
				//if(start_adv == 1)
				array_of_cids[k] = hash_node->conn_list->cid;
				hash_node->conn_list = hash_node->conn_list->next;
				}

				connection->cid = current_connection_id;
				connection->next = NULL; //was read
				connection->pointer_to_hashnode = hash_node;  //making the DS which was discussed.
				hash_node->conn_list = connection;
				
				if(last_marker[current_connection_id]!=NULL){  //setting the last marker
                        	past = last_marker[current_connection_id];
                        	last_marker[current_connection_id] = connection;
                        	past->next_pointer_to_thisconn = connection;
                                }
                		else
                		last_marker[current_connection_id] = connection;

                		if(start_marker[current_connection_id]==NULL){
                		connection->next_pointer_to_thisconn = connection;
                		start_marker[current_connection_id] = connection;
                		}
                		else
                		connection->next_pointer_to_thisconn = start_marker[current_connection_id]; //setting the last pointer in this list to the start pointer in our map list.

				/*if(last_marker[current_connection_id]!=NULL){
				past = last_marker[current_connection_id];
				past->next_pointer_to_thisconn = cid;	
				last_marker[current_connection_id] = past;}*/
				if(start_adv == 0)  //this bit is passed.If not advertise just return.
					{
					printf("redundancy is %d\n",redundancy);
       				 	return (NULL);
					}
				if(present_connection_id!=current_connection_id){  //the control will come here if start_adv = 1
				array_of_cids.clear();
				first = 1;
				start_point_firsttime = 1; //this is here because we need to keep updating the connection(hash sequence pointer) whhcih will be reset tp start as soon as the connection changes.
				previouspacket = packetnumber;
				}
				if(packetnumber - previouspacket == 2)   //start to build the backup using 2 packets.
				check_for_unique_cids.clear();
				if (start_adv == 1 && first==1) //to store the hashes from the first two packets.
				{
					numberofhashes++;
					flag_lib=1;
					present_connection_id = current_connection_id; //store the present connection id.
					if(packetnumber - previouspacket<=2){
					int k=0;
					read_feedback = (struct connlist*)hash_node; //start reading all the connections relevant to this hash seen.
					unique_hashes_seen[(char*)read_feedback->pointer_to_hashnode->key] = 1; // store all hte hashed seen.
					while(read_feedback!=NULL)
					{
						if(k<10){
						if(current_connection_id != read_feedback->cid)
						if(check_for_unique_cids[read_feedback->cid] != 1)
						check_for_unique_cids[read_feedback->cid] =1;
						if(check_for_unique_cids[read_feedback->cid] == 1)
						{
						array_of_cids[read_feedback->cid] += 1;  //add the connections to this map and note the frequency of them.
						//array_cid[feedback_cids] = read_feedback->cid;
						k++;
						}
						else
						continue;}
						else
						break;
					feedback_cids++;
					read_feedback = read_feedback->next;
					if(read_feedback->next==NULL)
					break;
					}	
				      }
					else{  //control will come here once packetnumber- previous packet > 2
					int hmax=0;
					for(std::map<int, int>::iterator it=array_of_cids.begin() ;it!= array_of_cids.end(); it++){
					if((*it).second > hmax){
						hmax=(*it).second;
						best_connection = (int)(*it).first;  //calculate the best connection
					}}
					check_for_unique_cids.clear();
					unique_hashes_seen.clear();//check whether you need the hashes from the first 2 packets or not.
					//choose best connection .. ask shruti di abt adding the connection also.
					first = 0;//this will hapenn only after 2 packets have been analysed.
					}
				}

				if(first == 0) //when to enter the hashes matching and advertising section..only after the best cid is chosen.
				{
				number_of_hashes_traversed = 0;
				if(flag_lib){
				store_packetnumber = packetnumber;
				last_hash = hash_number;
				array_of_cids_per_packet.clear();
				flag_lib=0;
				//if(packetnumber == packet_number)
				start = start_marker[best_connection];
				}
				if(last_hash!=1) //now this will be performed once for the first time and till we reac hteh last hash which is known by the passed bit value.
					{
					read_feedback = (struct connlist*)hash_node;
					unique_hashes_seen[(char*)read_feedback->pointer_to_hashnode->key]=1;
					array_of_cids[read_feedback->cid] += 1; //total HITS
					array_of_cids_per_packet[read_feedback->cid] += 1; //NEW HITS
					return NULL;
					}
				else
				{
				read_feedback = (struct connlist*)hash_node;
                                unique_hashes_seen[(char*)read_feedback->pointer_to_hashnode->key]=1;
				array_of_cids[read_feedback->cid] += 1;  //total HITS
				array_of_cids_per_packet[read_feedback->cid] += 1; //NEW HITS
				flag_lib=1;
				//close this at the end of everythin since the advertisements will happend after all the hashes for tht packet have come.
				if(start_point_firsttime)
				{
				//start = start_marker[best_connection]; //already done above
				start_point_firsttime = 0;
				}
				else
				{
				int max=0;
				for(std::map<int, int>::iterator it=array_of_cids_per_packet.begin() ;it!= array_of_cids_per_packet.end(); it++)
				{
				if(array_of_cids[(*it).first] > max)    // getting the best connection based on the new hits.
					max = array_of_cids[(int)(*it).first];
					best_connection = (int)(*it).first;
				}
				start = current_marker[best_connection];
				}
				while(start->next_pointer_to_thisconn!=NULL)
				{
				if(number_of_hashes_traversed > 20)
					break; //since we traversed till 20 and found how many ever matches. now take the counter pointer and start advertising from there.
				if(unique_hashes_seen[(char*)start->pointer_to_hashnode->key] == 1)
					counter = start->next_pointer_to_thisconn;
				//if(compare_key(start->pointer_to_hashnode->key,key)){
				//	int advertised=0;
				current_marker[best_connection] = start;//initialize current_pointer to some map / pointer till where we have traversed.
				start=start->next_pointer_to_thisconn;
				//}
				number_of_hashes_traversed++;
				}
					int advertised=0,last=0;
				      while(counter->next_pointer_to_thisconn!=NULL)//or start.
                                        {
                                        if(advertised<=20){ //now advertise 20 hashes starting from the counter pointer.
                                        advertised++;
					for(;j<20;j++){
					hashes_array[last] = (char*)start->pointer_to_hashnode->key;
					last++;
					}
					counter = counter->next_pointer_to_thisconn;
                                        //make_packet(start->pointer_to_hashnode->key);
                                        //map_insert_feedback(feedback,start->hash->key,keylen,status);
					}
                                                else {
						read_feedback = (struct connlist*)hash_node;
						unique_hashes_seen.clear();
					unique_hashes_seen[(char*)read_feedback->pointer_to_hashnode->key]=1;
						return &hashes_array;}
						//break;
					}
				
				//start logic and advertising.
				}
           			// return(nxt_hash_node);
       					 }
				//printf("%d",*(int*)hash_node->value);
                                hash_node = hash_node->nxt;
				//printf("after one move\n");
                        }}
			connection->cid = current_connection_id;
			connection->next = NULL;
			connection->pointer_to_hashnode = second;
                if(last_marker[current_connection_id]!=NULL){
                        past = last_marker[current_connection_id];
                        last_marker[current_connection_id] = connection;
                        past->next_pointer_to_thisconn = connection;
                                }
                else
                last_marker[current_connection_id] = connection;

                if(start_marker[current_connection_id]==NULL){
                connection->next_pointer_to_thisconn = connection;
                start_marker[current_connection_id] = connection;
                }
                else
                connection->next_pointer_to_thisconn = start_marker[current_connection_id];


			/*if(last_marker[current_connection_id]!=NULL){
			past = last_marker[current_connection_id];
			cid->next_pointer_to_thisconn = start_marker[current_connection_id];
			cid->hash = second;
			past->next_pointer_to_thisconn = cid;
			past = past->next;
			last_marker[current_connection_id] = past;
				}*/
			second->conn_list = connection;
			second->key = (char*)key;
                	second->value = (char*)value;
                	second->nxt = hash_node;
                	hash_node->nxt = NULL;
			map_mobile->table[hash] = second;
			//second = NULL;
                	map_mobile->size++;
			return NULL;
			//printf("found nul\n");
				}
		else //adding connections
		{

		connection->cid = current_connection_id;
		connection->next = NULL;
		connection->pointer_to_hashnode=hash_node;

		if(last_marker[current_connection_id]!=NULL){
                        past = last_marker[current_connection_id];
                        last_marker[current_connection_id] = connection;
                        past->next_pointer_to_thisconn = connection;
                                }
                else
                last_marker[current_connection_id] = connection;		

		if(start_marker[current_connection_id]==NULL){
		connection->next_pointer_to_thisconn = connection;
		start_marker[current_connection_id] = connection;
		}
		else  //we do not need to point the last to the start probably.
		connection->next_pointer_to_thisconn = start_marker[current_connection_id];

		hash_node->conn_list = connection;
		hash_node->key = (char*)key;
		hash_node->value = (char*)value;
		hash_node->nxt = NULL;
		map_mobile->table[hash] = hash_node;

		map_mobile->size++;}

		flag_lib = 1;}	
    /* now pme is at the end of the list on that index */
    if (hash_node == NULL) {
	//printf("how come\n");
        //printlog(LOG_WARN, "util.c: insert failed, malloc failure");
        return NULL;
    }
	//printf("exiting");
    return NULL;//&hashes_array;
}

