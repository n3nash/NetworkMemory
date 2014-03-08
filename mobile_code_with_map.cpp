//insert into the big hash table structure database

//read thru netfilter

//print packet (if only data is transfered then perform the old funcitonality else if data+hashes then we need to check).
#include "mobile_code.h"
#include<map>
#include<utility>
#include<iostream>
#include<stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/sha.h>
#include <search.h>
#include <sys/time.h>
#include <string.h>
//#include <pcap/sll.h>
//defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

#define IP_PROTO_TCP (6)
#define IP_PROTO_UDP (17)

#define ADVERTISED 202
#define VERBOSE 0
#define VERBOSE1 0
#define MAX_MARKS 10000
#define MAX_SEG_SIZE 1500
#define buffer_size 150000
double total_time = 0;
typedef unsigned short u16;
typedef unsigned long u32;

//struct hsearch_data *htab,*htab2;

int count_hash_table;
long long num[] = {0,1,2,3,4,5,6,7};


int valueList[256]; //Reference table where I store the values for fast lookup
long long p1,q1,m1,b1;
int store_marks[MAX_MARKS];
uint16_t read_header_value=0,type=0;


char status_hash[2];
char status_clear[2];
char status_header[2];
char read_status[2];
char pStatus[2]; //Pseudo header. Kept global to avoid passing between helper functions and packet manip function
char pStatusHash[2]; //Pseudo header for hashes. Always constant. Kept global to avoid passing between 

#define CLEARDATA 200
#define TCP 6
#define MIXED 201
//#define ACK_CLEAR 202
#define ACK_HASHES 202

struct values
{
int length;
char *data;
};

typedef struct values values;

unsigned char *modify_data_udp;

int len_hash=0,choice=0,entered=0,flag;
char new_payload[150000];

map_handle *map_mobile;
struct values h_data;
//std::map<char*,struct values> h_data;
void *rethashes;
std::map<char*,values> store_mapping_map;

u_char *data_advertisements;
long int packetnumber=0;
int limit = 1000;
std::map<int , char*> hashes;
//char **hashes;


int VBWC_bytes = 0,hashes_accumulated=0,new_pay_len=0,list_seen=0;

void initialize_hashTable(){

map_mobile = allocate_map();

}


u_short in_cksum(const u_short *addr, register u_int len) //, int csum) 
{ 
    int nleft = len; 
    const u_short *w = addr; 
    u_short answer; 
    int sum = 0; //csum;

    /* * Our algorithm is simple, using a 32 bit accumulator (sum), * we add sequential 16 bit words to it, and at the end, fold * back all the carry bits from the top 16 bits into the lower * 16 bits. */ 
    while (nleft > 1) { sum += *w++; nleft -= 2; } if (nleft == 1) sum += htons(*(u_char *)w<<8);

    /* * add back carry outs from top 16 bits to low 16 bits */ 

    sum = (sum >> 16) + (sum & 0xffff); 
    /* add hi 16 to low 16 */ sum += (sum >> 16); 

    /* add carry */ answer = ~sum; 
    /* truncate to 16 bits */ return (answer);
} 

//Helper functions by gkaushik for bit-wise manipulations for pseudo headers
int get_bit(int element)
{
    uint byte_index = element/8;
    uint bit_index = element % 8;
    uint bit_mask = ( 1 << bit_index);

    return ((pStatus[byte_index] & bit_mask) != 0);
}

int get_bit_hash(int element)
{
    uint byte_index = element/8;
    uint bit_index = element % 8;
    uint bit_mask = ( 1 << bit_index);

    return ((pStatusHash[byte_index] & bit_mask) != 0);
}

void set_bit_hash (int element)
{
    uint byte_index = element/8;
    uint bit_index = element % 8;
    uint bit_mask = ( 1 << bit_index);

    pStatusHash[byte_index] |= bit_mask;
}


void set_bit (int element)
{
    uint byte_index = element/8;
    uint bit_index = element % 8;
    uint bit_mask = ( 1 << bit_index);

    pStatus[byte_index] |= bit_mask;
}

void clear_bit (int element)
{
    uint byte_index = element/8;
    uint bit_index = element % 8;
    uint bit_mask = ( 1 << bit_index);

    pStatus[byte_index] &= ~bit_mask;
}


u16 ip_sum_calc(u16 len_ip_header, u16 buff[])
{
    u16 word16;
    u32 sum=0;
    u16 i;

    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0;i<len_ip_header;i=i+2){
        word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
        sum = sum + (u32) word16;	
    }

    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16)
        sum = (sum & 0xFFFF)+(sum >> 16);

    // one's complement the result
    sum = ~sum;

    return ((u16) sum);
}



int expo(long long value,long long expo,long long mod)
{

    long long temp,temp2, answer = 1;

    int i=0;	

    //Corner cases for Mod non-positive numbers.
    if(mod == 0 || mod < 0)
    {
        printf("Modular arithmetic is not defined for 0 or negative numbers \n \n Exiting... \n");
        exit(1);
    }
    temp2 = expo;
    while(temp2)
    {
        i++;
        temp2 = temp2>>1;
    }

   // temp2 = expo;

    for(;i>0;i--)
    {
        answer = (answer * answer) % mod;
        if(expo>>(i-1)&1)
        {
            answer = (answer * value) % mod;
        }

    }

    return answer;
}

void initialize_rabin()
{

    int i,j;

    p1 = 1048583;
    b1 = 7;
    m1 = 8;
    q1 = expo(p1,b1,m1);
	printf("%lld",q1);
    for(i=0;i<256;i++)
    {
        valueList[i] = i * (int) q1;
    }

}


uint16_t set_header_hash(int length)
{
	uint16_t header;	
	header = header | 0x8000;
	header = header | length;
	status_hash[0] = header / 256;
	status_hash[1] = header % 256;
	//sprintf(status_hash,"%d",header);
}

uint16_t set_header_clear(int length)
{
	uint16_t header;
	header = header & 0x0000;
	header = header | length;
	status_clear[0] = header / 256;
	status_clear[1] = header % 256;
	//sprintf(status_clear,"%d",header);
}

void clear_header()
{
	status_header[0] = ' ';
	status_header[1] = ' ';
}

uint16_t read_header()
{
	read_header_value = 0;
	type = 0;	
	read_header_value = read_status[0] & 0x8000;
	type = read_header_value;
	read_header_value = read_header_value | ((read_status[0]<<8) & 0x7f00);
	read_header_value = read_header_value | ((read_status[1]));
}

values look_up_mapping(char *hash)
{
	char temp[1000];
	int len_hash = store_mapping_map[hash].length;
	strcpy(temp,store_mapping_map[hash].data);
	return store_mapping_map[hash];
}


void store_mapping(char *hash,char *data,int length)
{
	char store[1000];
	strncpy(store,data,length);
	strncpy(store_mapping_map[hash].data,store,length);
	store_mapping_map[hash].length = length;
//void look up needed but can we couple along with this only.
}


static u_int32_t packet_advertise (struct nfq_data *tb,int *newSize,int start_adv)
{
    int id = 0,newRet,original_bytes=0,ret=0;
    int packet_finished = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    unsigned char *data;
    u_char *pkt_ptr;
    char new_ack_payload[1500];
    ret = nfq_get_payload(tb, (char **)&data);
    int ether_type = ((int)((pkt_ptr)[12]) << 8) | (int)(pkt_ptr)[13]; 
    int ether_offset = 0; 
        if (ether_type == ETHER_TYPE_IP) //most common 
        ether_offset = 14;

     	/*u_short ether_type_sll;
	struct sll_header *sllp;
	sllp = (struct sll_header *)pkt_ptr;
	ether_type_sll = sllp->sll_protocol;
	if(ether_type_sll == 8)
		{
			pkt_ptr += 16;
		}*/

    pkt_ptr += ether_offset;  //skip past the Ethernet II header 
    u_int size_ip;
    VBWC_bytes += (ret - 20);	//just IP payload

    pkt_ptr = (u_char *)data;
	struct ip *ip_hdr =  (struct ip *) pkt_ptr;
     int pay_len=0;
    pkt_ptr += size_ip;
    pay_len = ret-size_ip;
    u_char* data_udp = (u_char*)pkt_ptr;
    if(ip_hdr->ip_p == TCP)
	{
	int i=0;
	i = i +2;
	while(new_payload[hashes_accumulated] != '=')
		{
		if(hashes_accumulated == buffer_size - 1)
			hashes_accumulated = 0;
		new_ack_payload[i++] = new_payload[hashes_accumulated++];
		}
	if(i > 2)
		{
		if(hashes_accumulated == buffer_size - 1)
			hashes_accumulated = 0;
		new_payload[hashes_accumulated++] = ' ';
		//list_seen++;
		int j;
		for (j=0;j<i;j++)
		{
		data[j] = new_ack_payload[j];
		}
		set_header_hash(i);
		new_ack_payload[0] = status_hash[0];
		new_ack_payload[1] = status_hash[1];
		i += size_ip;
    		ip_hdr->ip_p = ACK_HASHES;
    		ip_hdr->ip_len = htons(i);
    		ip_hdr->ip_sum = in_cksum((unsigned short *) ip_hdr,sizeof(struct ip));
    		*newSize = i;//newRet;
		return id;		
		}
	else
		return id;


	}
}


static u_int32_t print_pkt (struct nfq_data *tb,int *newSize,int packetnumber , int start_adv)
{
    int id = 0,newRet,original_bytes=0;
    int packet_finished = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    int ret;
    unsigned char *data;
    unsigned char *data_advertised_packet;
	char sourceIP[INET_ADDRSTRLEN],destinationIP[INET_ADDRSTRLEN];
	uint16_t sourcePORT,destinationPORT;
    //unsigned char *h_data = NULL;
    u_char *pkt_ptr;
	int moving_copy = 0;


    ret = nfq_get_payload(tb, (char **)&data);

    VBWC_bytes += (ret - 20);	//just IP payload

    pkt_ptr = (u_char *)data;
    int ether_type = ((int)((pkt_ptr)[12]) << 8) | (int)(pkt_ptr)[13]; 
    int ether_offset = 0; 
    u_int size_ip;

    if (ether_type == ETHER_TYPE_IP) //most common 
        ether_offset = 14;

     	/*u_short ether_type_sll;
	struct sll_header *sllp;
	sllp = (struct sll_header *)pkt_ptr;
	ether_type_sll = sllp->sll_protocol;
	if(ether_type_sll == 8)
		{
			pkt_ptr += 16;
		}*/

    pkt_ptr += ether_offset;  //skip past the Ethernet II header 
    struct ip *ip_hdr =  (struct ip *) pkt_ptr;

        printf("Protocol: %d \n",ip_hdr->ip_p);

    size_ip = 4*(ip_hdr->ip_hl);
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);

        }
	   struct tcphdr *tcp_hdr=(struct tcphdr *) pkt_ptr;
    struct udphdr *udp_hdr=(struct udphdr *) pkt_ptr;
  
	if(ip_hdr->ip_p == 6){
   
	sourcePORT = ntohs(tcp_hdr->source);
	
    destinationPORT = ntohs(tcp_hdr->dest);}
	if(ip_hdr->ip_p == 17)
	{   
 sourcePORT = ntohs(udp_hdr->source);
    destinationPORT = ntohs(udp_hdr->dest);
				}
    inet_ntop(AF_INET, &(ip_hdr->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), destinationIP, INET_ADDRSTRLEN);
	int current_connection_id = add_connection(sourceIP,destinationIP,sourcePORT,destinationPORT);
//starting from now we need to see if the protocol is 200 or semthin that means that the packet is pure / clean without any hashes/

    int pay_len=0;
    pkt_ptr += size_ip;
    pay_len = ret-size_ip;
    u_char* data_udp = (u_char*)pkt_ptr;
    //ip_hdr->ip_sum = 0;
    unsigned short seg_len=0;
    //ip_hdr->ip_sum = ip_sum_calc(size_ip,ip_hdr);
    if (ip_hdr->ip_p == TCP)
    {
        int i,f,result=0,result_mod=0,j,counting = 0,last_hit=0,last_mark=0,all_original = 1, too_small = 0, k =0, f1=0;
        //new_pay_len=ret;
        pkt_ptr += 20;
            printf("\n Old Payload ----- Protocol TCP --- Completely Unhashed \n");

       for(i=0,j=0;i<8;i++)
        {
            result += (int)data_udp[i] * expo(p1,num[7-i],m1);
        }

        result_mod = result % 8;

        if(!result_mod){
            //printf("\n -- Hit! at %d - Count no. %d -- \n",i,counting++);//changed
		store_marks[j++] = i;}

        for(;i<pay_len;i++)
        {

            result = result - valueList[(int)data_udp[i-8]];
            result = result * p1;
            result = result % m1;
            result += (int) data_udp[i] % 8;
            result_mod = result % 8;
            if(!result_mod && (i-last_hit) > 8)
            {  				
                //printf("\n -- Hit! at %d - Count no. %d -- \n",i,counting++);//changed
                store_marks[j++] = i;
                last_hit = i;
		
            }

        }
        store_marks[j] = pay_len;

        for(i=0;i<j;i++)
            if(VERBOSE)
                printf("==\n%d :: %d \n==",i+1,store_marks[i]);


        for(i=0; i<=j; i++)
        {
            unsigned char *sha1 = (unsigned char*)malloc(20);
            int replace_flag = 0;

            //strncpy(segment[number_of_entries],data_udp + last_mark,store_marks[i]-last_mark);
            //segment[store_marks[i]-last_mark] = '\0';
                      if(i<j)			
            {	 	
                SHA1(data_udp + last_mark,store_marks[i]-last_mark,sha1);//everything but final segment

            }
            else
            {
		if((store_marks[i] - last_mark) > 8)
		{

                    SHA1(data_udp + last_mark,pay_len-last_mark,sha1);
		}
                else
                {
                       //printf(" \n -- too small -- \n");
                    too_small = 1;

                }
            }


            if(i < pay_len && !too_small)
            {
                    int ja;	
                    flag = 1;
			if(i==j)
				packet_finished = 1;
		    store_mapping((char*)sha1 ,(char*)(data_udp + last_mark),store_marks[i]-last_mark);

       		    rethashes = map_insert(map_mobile,(void*)sha1,(void*)store_marks[i]-last_mark,current_connection_id,start_adv,packetnumber,packet_finished);
              
		    std::map <int, char*> &hashes = *(static_cast<std::map<int, char *> *>(rethashes));

		
		    if(!hashes.empty())
			{
			if(new_pay_len == buffer_size - 2)
				new_pay_len = 0;
			entered = 1;
			for(std::map<int,char* >::iterator ii=hashes.begin(); ii!=hashes.end() ; ii++)
			{
			sha1 = (unsigned char*)(*ii).second;
                	for(k=0;k<20;k++)
                	{
			if(new_pay_len == buffer_size - 1)
				new_pay_len = 0;
                    	new_payload[new_pay_len++] = sha1[k];
                		}
			}
			if(new_pay_len == buffer_size - 1)
				new_pay_len = 0;
			new_payload[new_pay_len++] = '=';
			set_header_hash(new_pay_len);
			//new_payload[0] = status_hash[0];
                	//new_payload[1] = status_hash[1];
			}
             
  
             }
   
            if(i<j)
                last_mark = store_marks[i];
	}//clasoe of for
//set = 1;
return id;
      } //close of "if"


//now if the packet contains hashes then we have set its heaser to some value and then process...

    if (ip_hdr->ip_p == MIXED)
    {
	u_char modify_data_udp[1500];
        int i,i9,j9,number=0,j,ja;
        //u_char new_payload[1500]
            printf("\n Old Payload ----- Protocol 202 --- Mixed --- ret %d\n",ret);
	int result = 0,result_mod = 0,counting = 0,last_hit = 0, last_mark = 0, too_small = 0;
        for(i=0;i<pay_len;)
        {
            number = 0;		
            flag = 1;
	    clear_header();
            status_header[0] = data_udp[i];
            status_header[1] = data_udp[i+1];

            i = i+2;
	    read_header();
            if(type) //mixed will have hash + clear //SEE WHAT IS IT FROM THE HEADER !!!!!READING CODE ????!!!!!!!!!!!!!!!!
            {			
                    printf("\n == Hash Entry == \n");

                unsigned char *sha1 = (unsigned char*)malloc(20);
		unsigned char *sha_insert;
                int r = 0;
                for(;j<i+20;j++,r++)
                { 
                    sha1[r] = data_udp[j];			 
                }
		h_data = look_up_mapping((char*)sha1);

                //h_data = hmap_get(htab, sha1);
                if (h_data.data == NULL) 
                {
		    printf("there is no coressponding data for this hash!");
                    printf("Not found :-( entry failed\n VBWC FAILURE! \n \n");


                }
                else	
                {
                    char* payload;
			clear_header();
		    	//modify_data_udp[moving_copy++] = [0];
                	//modify_data_udp[moving_copy++] = pStatus[1];	
                	clear_bit(1);
           	 	seg_len=(unsigned short)(h_data.length);
                	//set_number_header(h_data.length);				
               		// modify_data_udp[moving_copy++] = pStatus[0];  //setting headers for segments.
               		// modify_data_udp[moving_copy++] = pStatus[1];
			int k;
                	for(k=0;k<h_data.length;k++)
                	{
                        	printf("%x\t",data_udp[k]);		
                    	modify_data_udp[moving_copy++] = h_data.data[k];	
                	}

			if(i == pay_len-1)
				packet_finished = 1;

		rethashes = map_insert(map_mobile,(void*)sha1,(void*)h_data.length,current_connection_id,start_adv,packetnumber,packet_finished);//(ep == NULL)
		 	//wrte the return part when the hashes are returned or advertised or whatever.
			//store_mapping(hash , data_udp + last_mark); // store the mapping here if the data's sha has been calculated.
			std::map <int, char*> &hashes = *(static_cast<std::map<int, char *> *>(rethashes));

			if(!hashes.empty())
			{
			entered = 1;
			if(new_pay_len == buffer_size - 2)
				new_pay_len = 0;
			//new_payload[new_pay_len++] = pStatusHash[0];
                	//new_payload[new_pay_len++] = pStatusHash[1];

			for(std::map<int,char*>::iterator ii=hashes.begin(); ii!=hashes.end() ; ii++)
			{
			sha1 = (unsigned char*)(*ii).second;
                	for(k=0;k<20;k++)
                	{
			if(new_pay_len == buffer_size - 1)
				new_pay_len = 0;
                    	new_payload[new_pay_len++] = sha1[k];
                		}
			}
			if(new_pay_len == buffer_size - 1)
				new_pay_len = 0;
			new_payload[new_pay_len++] = '=';
			}

			seg_len = h_data.length;
                    	
                }

                i = i+20;  
		//END OF HASH PRSENT HERE
            }
            else  //for the if(getbit1) now here this else means there is no hash content only clear content.
            {
                if(VERBOSE1)			
                    printf("\n == Cleartext Entry == \n");
                char buffer[MAX_SEG_SIZE];
                unsigned char *sha2=(unsigned char*)malloc(20);
                int r2 = 0,ja,k=0;
                number = 0;
                if(!type)
                    number = read_header_value; //get teh length is the clear data.
			int seglen=0;
			seglen = read_header_value;
				//ned the length of the segment.!!!!!!!!!!!!!!!
			//modify_data_udp[moving_copy++] = pStatus[0];
                	//modify_data_udp[moving_copy++] = pStatus[1];	
                	clear_bit(1);
           	 	seg_len=(unsigned short)number/256;			
               		// modify_data_udp[moving_copy++] = pStatus[0];  //setting headers for segments.
               		// modify_data_udp[moving_copy++] = pStatus[1];

                	for(k=i;k<i+seglen;k++)
                	{
                        	printf("%x\t",data_udp[k]);		
                    	modify_data_udp[moving_copy++] = data_udp[k];	
                	}
   
                    //store the length of the payload into the first 2 bytes of the array entry
                    //segment[number_of_entries][0]=number/256;
                    //segment[number_of_entries][1]=number%256;
			
			//calculating the sha1 for the data segment that is there in the mixed packet..here we need to store the mapping.on the ap side when we send the advertised packet this thing will not be ther since there will be only hashed iont he packet.
                        SHA1(data_udp+i,number,sha2);

			store_mapping((char*)sha2,(char*)(data_udp+i),number);
                    
 			//we also need to add this hash to the mobile cache so we call map_insert here.
			if(i == pay_len-1)
				packet_finished = 1;
                    rethashes = map_insert(map_mobile,(void*)sha2,(void*)number,current_connection_id,start_adv,packetnumber,packet_finished);//(ep == NULL) 
			//do code for the return value of the hashes to put into a new payload to be sent to the ap as advertisements
			std::map <int, char*> &hashes = *(static_cast<std::map<int, char *> *>(rethashes));

			if(!hashes.empty())
			{
			entered = 1;
			if(new_pay_len == buffer_size - 2)
				new_pay_len = 0;
			//new_payload[new_pay_len++] = pStatusHash[0];
                	//new_payload[new_pay_len++] = pStatusHash[1];
			for(std::map<int,char*>::iterator ii=hashes.begin(); ii!=hashes.end() ; ii++)
			{
			
			sha2 = (unsigned char*)(*ii).second;
                	for(k=0;k<20;k++)
                	{
			if(new_pay_len == buffer_size - 1)
				new_pay_len = 0;
                    	new_payload[new_pay_len++] = sha2[k];
                    	
                		}
			}
			if(new_pay_len == buffer_size - 1)
				new_pay_len = 0;
			new_payload[new_pay_len++] = '=';
			}
			//you need to create a new que. pass a new struct nfq and do new get_payload(data).now pass the constructed data into data
	}//else

         i = i + number;

           } //end of for
	int i_new=0;
    for(i_new=0;i_new<moving_copy;i_new++)
       {
            data_udp[i_new] = modify_data_udp[i_new]; //copy all the contents of the new_payload into the data_udp which is the original pointer that
        }
    moving_copy += size_ip;
    ip_hdr->ip_p = MIXED;
    ip_hdr->ip_len = htons(moving_copy);
    ip_hdr->ip_sum = in_cksum((unsigned short *) ip_hdr,sizeof(struct ip));
    *newSize = moving_copy;
return id;
        } //end of 'if' for hashes

}


//here we need to make 2 packets one to send to the upper layer if it has hases taht is if the protocol in header is ddeffrerent and one to make for the advertised hashes. do this and see when to advertise..
//copy the code from here to make the hashes store vala funcitons.


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
    char *send_data;
    int i,newSize;
    struct timeval tim;
    gettimeofday(&tim,NULL);
    u_int32_t id;
    double t1 = tim.tv_sec + (tim.tv_usec/1000000.0);
    packetnumber++;
	if(packetnumber > limit)
	{
	printf(" %d packets have passed \n",limit);
	scanf("do you want to start advertising , enter 1 for yes 0 for No %d\n",&choice);
		if(choice == 1)
    		id = print_pkt(nfa, &newSize, packetnumber,1);
		else
		scanf(" Enter new packet limit %d \n",&limit);
	}
	if(choice == 0)
		id = print_pkt(nfa, &newSize, packetnumber,0);

    gettimeofday(&tim,NULL);
    double t2 = tim.tv_sec + (tim.tv_usec/1000000.0);
    total_time = total_time + (t2-t1);
    printf("\n===========================\n");
    printf("Time elapsed so far = %.61f sec \n Average time per packet = %.61f sec \n",total_time,total_time/(float)id);
    printf("Number that makes more sense = %f packets/sec", (float)id/total_time);
    printf("\n===========================\n");
    i = nfq_get_payload(nfa,&send_data);
    printf("entering callback\n ---- newRet : %d %d \n \n",newSize,i);
    return nfq_set_verdict(qh, id, NF_ACCEPT, newSize, (unsigned char*)send_data);
}


static int cb_send_acks(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)

{
    char *send_data;
    int i,newSize;
    struct timeval tim;
    u_int32_t  id;
    gettimeofday(&tim,NULL);
    double t1 = tim.tv_sec + (tim.tv_usec/1000000.0);
    packetnumber++;
	if(packetnumber > limit)
	{
	printf(" %d packets have passed \n",limit);
	scanf("do you want to start advertising , enter 1 for yes 0 for No %d\n",&choice);
		if(choice == 1)
 		id = print_pkt(nfa, &newSize, packetnumber,1);
		else
		scanf(" Enter new packet limit %d \n",&limit);
	}
	if(choice == 0)
	id = print_pkt(nfa, &newSize, packetnumber,0);

    gettimeofday(&tim,NULL);
    double t2 = tim.tv_sec + (tim.tv_usec/1000000.0);
    total_time = total_time + (t2-t1);
    printf("\n===========================\n");
    printf("Time elapsed so far = %.61f sec \n Average time per packet = %.61f sec \n",total_time,total_time/(float)id);
    printf("Number that makes more sense = %f packets/sec", (float)id/total_time);
    printf("\n===========================\n");
    i = nfq_get_payload(nfa,&send_data);
    printf("entering callback\n ---- newRet : %d %d \n \n",newSize,i);
    return nfq_set_verdict(qh, id, NF_ACCEPT, newSize, (unsigned char*)send_data);
}



int main(int argc, char **argv)
{

//copy all of this again for another queue.
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    initialize_hashTable();
    initialize_rabin();
    flag = 0;
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        //exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '1'\n");
    qh = nfq_create_queue(h,  1, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

       printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    printf("Packet Mode Set");
    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         pStatusHash[0] = pStatus[0];
         pStatusHash[1] = pStatus[1];
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    //exit(0);


    struct nfq_handle *h1;
    struct nfq_q_handle *qh1;
    struct nfnl_handle *nh1;
    int fd1;
    int rv1;
    char buf1[4096] __attribute__ ((aligned));
    flag = 0;
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
      //  exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h1, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h1, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
       // exit(1);
    }

    printf("binding this socket to queue '1'\n");
    qh = nfq_create_queue(h1,  2, &cb_send_acks, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

       printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh1, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    printf("Packet Mode Set");
    fd = nfq_fd(h);

    for (;;) {
	printf("came here\n");
        if ((rv1 = recv(fd1, buf1, sizeof(buf1), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h1, buf1, rv1);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         pStatusHash[0] = pStatus[0];
         pStatusHash[1] = pStatus[1];
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv1 < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh1);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h1, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h1);

    exit(0);


}

//create another queue for the packets

