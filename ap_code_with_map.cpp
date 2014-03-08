#include "ap_code.h"
#include <sys/time.h>
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
#include <string.h>
#include <linux/types.h>

//#include<pcap/sll.h>
//defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

#define IP_PROTO_TCP (6)
#define IP_PROTO_UDP (17)

#define ADVERTISED 202
#define MIXED 201
#define VERBOSE 0
#define VERBOSE1 0
#define MAX_MARKS 10000
#define MAX_SEG_SIZE 1500
#define TCP 6

double total_time = 0;
typedef unsigned short u16;
typedef unsigned long u32;

//struct hsearch_data *htab,*htab2;

int count_hash_table;
long long num[] = {0,1,2,3,4,5,6,7};
char status[2];

int valueList[256]; //Reference table where I store the values for fast lookup
long long p1,q1,m1,b1;
int store_marks[MAX_MARKS];

char status_hash[2];
char status_clear[2];
char read_status[2];
uint16_t read_header_value=0,type=0;

char pStatus[2]; //Pseudo header. Kept global to avoid passing between helper functions and packet manip function
char pStatusHash[2]; //Pseudo header for hashes. Always constant. Kept global to avoid passing between 

int flag=0,regular_hit=0,feedback_hit=0;

map_handle *regular , *feedback;

void initialize_hashTable(){

regular = allocate_map();
feedback = allocate_map();
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



void initializeHashHeader()
{

    //Donkey work initialization. Just to be safe.
    int i, k = 20;

    for(i=1;i<17;i++)
    {
        clear_bit(i);
    }

    pStatusHash[0] = pStatus[0];
    pStatusHash[1] = pStatus[1];

    for(i=0;i<11;i++) 
    {
        if((k & ( 1 << i )) >> i) //neat way to find set bit. src: Google search.
        {
            set_bit(16-i);
        }
        else
        {
            clear_bit(16-i);
        }

    }

    set_bit(1);

    pStatusHash[0] = pStatus[0];
    pStatusHash[1] = pStatus[1]; 

    printf("\n --- Hash Headers Initialized!! --- \n");
}

void set_number_header(int set)
{
    int i,k = set,j,number = 0;
    if(VERBOSE)
        printf("\n===Setting Number Header====\n");
    for(i=1;i<17;i++)
    {
        clear_bit(i);
    }
    for(i=0;i<11;i++) 
    {
        if((k & ( 1 << i )) >> i) //neat way to find set bit. src: Google search.
        {
            set_bit(16-i);
        }
        else
        {
            clear_bit(16-i);
        }

    }

    for(i=0,j=16;j>=2;j--,i++)
    {
        if(get_bit(j))
            number |= 1 << i;
    }
    //printf("########### Setting length in header, set=%d, number=%d ##########\n", set, number);
    if(VERBOSE)
        printf("\n--- Number is %d --- \n",number);

    if(number%2)
    {
        set_bit(2);
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

uint16_t read_header()
{
read_header_value = 0;
type = 0;
read_header_value = read_status[0] & 0x8000;
type = read_header_value;
read_header_value = read_header_value | ((read_status[0]<<8) & 0x7f00);
read_header_value = read_header_value | ((read_status[1]));
}

/* * IP header checksum. * don't modifiy the packet. */ 

u_short in_cksum(const u_short *addr, register u_int len) 
{ 
    int nleft = len; 
    const u_short *w = addr; 
    u_short answer = 0; 
    int sum = 0; //= csum;

    /* * Our algorithm is simple, using a 32 bit accumulator (sum), * we add sequential 16 bit words to it, and at the end, fold * back all the carry bits from the top 16 bits into the lower * 16 bits. */ 

    while (nleft > 1) 
    { 

        sum += *w++; 

        nleft -= 2; 
    } 

    //if (nleft == 1) 
    //{
    //*(u_char *)(&answer)= *(u_char *)w;
    //sum +=answer;
    //}
    //sum += htons(*(u_char *)w<<8);

    /* * add back carry outs from top 16 bits to low 16 bits */ 

    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */ 
    sum += (sum >> 16); /* add carry */ 
    answer = ~sum;  /* truncate to 16 bits */ 
    return (answer);
} 

void set_header()
{
	        uint16_t header = 0;
		header = header | 0x10000000;
		//printf("%d\n",header);
		sprintf(status,"%d",header);
		//printf("%c %c\n",status[0],status[1]);
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

static uint32_t packet_advertised(struct nfq_data *tb,int *newSize,int has_advertised_hashes)
{
uint16_t header;
//if(ip_hdr->ip_p == ADVERTISED) //read the protocol.(after)
//{
//check for the segmnent bits that are set , extract those hashes and then call insert
//u_char *data_udp = packet;

u_char *modify_data;
int seg_len=0,status=0;
int newRet=0;
char modify_data_udp[1500];
int moving_copy=0,k=0;

int store_marks[MAX_MARKS];

    unsigned char *data ;
    int id = 0,ret=0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 

        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
            id = ntohl(ph->packet_id);
            if(VERBOSE)
                printf("h/w_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
        }

    ret = nfq_get_payload(tb, (char **)&data); //get the packet data.

    if (ret >= 0)
    {
        int i;
        if(VERBOSE1)       printf("payload_len=%d ", ret);
        i = 8;
    }      

//till here we have now got the packet.Now we need to start analysing the packet details

    //pkt_ptr = (u_char *)data;

    u_char *pkt_ptr = (u_char*)data;

	/*u_short ether_type_sll;
	struct sll_header *sllp;
	sllp = (struct sll_header *)pkt_ptr;
	if(sllp!=NULL)
	ether_type_sll = sllp->sll_protocol;
	if(ether_type_sll == 8)
		{
	pkt_ptr += 16;
		}*/

    int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13]; 
    int ether_offset = 0; 

    if (ether_type == ETHER_TYPE_IP) //most common 
        ether_offset = 14; 

    pkt_ptr += ether_offset;  //skip past the Ethernet II header 
    struct ip *ip_hdr = (struct ip *)pkt_ptr;
		pkt_ptr+= 20;

    u_char *data_udp = pkt_ptr;
    ip_hdr->ip_sum = 0;

    int size_ip;

    size_ip = 4*(ip_hdr->ip_hl);

    pkt_ptr += size_ip;
    //u_char* data_udp = (u_char*)pkt_ptr; //data_udp is same as data_ip

        int i,i9,j9,number=0,flag =0,j,ja;
        //u_char new_payload[1500];
        int new_pay_len=0,set=1;
        int pay_len = ntohs(ip_hdr->ip_len); 
	pkt_ptr += 4*(ip_hdr->ip_hl);
        for(i=0;i<pay_len;)
        {
            number = 0;		
            flag = 1;
	    if(set){
	    set=0;
            read_status[0] = data_udp[i];
            read_status[1] = data_udp[i+1];
	    i = i+2;
	      }
                printf("Segment header %x %x\n", read_status[0],read_status[1]);
		read_header();
		printf("type is %d and length is %d\n",type, read_header_value);
                unsigned char *sha1 = (unsigned char*)malloc(20);
		//char *sha_recv = (char*)malloc(20);
		int sha_recv;
                int r = 0;
                    printf("Hash content:\t");
                for(;j<i+20;j++,r++)
                { 
                    sha1[r] = data_udp[j];			 
            
                }

                //ja = hsearch_r(e, FIND,&ep,htab);
		sha_recv = map_insert_regular_or_feedback(feedback,(void*)sha1,(void*)20,2); //hits we will calculate in the library funciton itslef
                //h_data = look_up_mapping(sha1);
                if (sha_recv == 1) 
                {
                    printf("Not found :-( entry failed\n VBWC FAILURE! \n \n");


                }
		number = 20;
                i = i + number; //number = 20.

	} //create the ACK packet or what?!!!!!!!!!!!!!!!!!!!
  		ip_hdr->ip_p = TCP;
            	newRet = 0;
		//data_udp =   ??
            	newRet += size_ip;

        	ip_hdr->ip_len = htons(newRet);
        	ip_hdr->ip_sum = in_cksum((unsigned short *) ip_hdr,sizeof(struct ip));
return id;
//}

//else
// return -1;

}

// whatver you need to pass has to be in the "data" variable which has the address to be put on the queue.

static uint32_t print_pkt (struct nfq_data *tb,int *newSize,int has_advertised_hashes)
{
uint16_t header;

u_char *modify_data;
int seg_len=0,status=0;
int newRet=0;
char modify_data_udp[1500];
int moving_copy=0,k=0;

int store_marks[MAX_MARKS];

    unsigned char *data ;
    int id = 0,ret=0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 

        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
            id = ntohl(ph->packet_id);
            if(VERBOSE)
                printf("h/w_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
        }

    ret = nfq_get_payload(tb, (char **)&data); //get the packet data.

    if (ret >= 0)
    {
        int i;
        if(VERBOSE1)       printf("payload_len=%d ", ret);
        i = 8;
    }      

//till here we have now got the packet.Now we need to start analysing the packet details

    //pkt_ptr = (u_char *)data;

    u_char *pkt_ptr = (u_char*)data;

	/*u_short ether_type_sll;
	struct sll_header *sllp;
	sllp = (struct sll_header *)pkt_ptr;
	if(sllp!=NULL)
	ether_type_sll = sllp->sll_protocol;
	if(ether_type_sll == 8)
		{
	pkt_ptr += 16;
		}*/

    int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13]; 
    int ether_offset = 0; 

    if (ether_type == ETHER_TYPE_IP) //most common 
        ether_offset = 14; 

    pkt_ptr += ether_offset;  //skip past the Ethernet II header 
    struct ip *ip_hdr = (struct ip *)pkt_ptr;
		pkt_ptr+= 20;
	u_char *data_udp = pkt_ptr;


    //if (ip_hdr->ip_p == IP_PROTO_TCP)    //||||||what about the acknowledged packet which is plain just ACK||||||
        //ip_hdr->ip_p = 200;
    //ip_hdr->ip_sum = 0;

    int size_ip;

    size_ip = 4*(ip_hdr->ip_hl);

    pkt_ptr += size_ip;
    //u_char* data_udp = (u_char*)pkt_ptr; //data_udp is same as data_ip


  	//struct ip *ip_hdr = (struct ip *)pkt_ptr;
        ret = ntohs(ip_hdr->ip_len); 
    if (ret >= 0)
    {
        int i;
      // printf("payload_len=%d ", ret);
        i = 8;
    }      
        if (size_ip < 20) 
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
 
        int i,j;


        char *to = (char *) malloc(11);
        int count = 0;
	//u_char *data_udp = pkt_ptr;
        //int k;

        int pay_len=ret;
	//totalB += pay_len;
        int result = 0,result_mod = 0,counting = 0,last_hit = 0, last_mark = 0, too_small = 0;
        int h=0;

        for(i=0,j=0;i<8;i++)
        {
            result += (int)data_udp[i] * expo(p1,num[7-i],m1);
        }

        result_mod = result % 8;

        if(!result_mod){
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
                store_marks[j++] = i;
                last_hit = i;
		
            }

        }
	
        store_marks[j] = pay_len ; 
 

        int all_original = 1;
        for(i=0; i<=j; i++)
        {
		//char *regular_hash,*feedback_hash;
		//regular_hash = (char*)malloc(sizeof(char)*30);
		//feedback_hash = (char*)malloc(sizeof(char)*30);
		int feedback_hash = 0 , regular_hash = 0;
            unsigned char *sha1 = (unsigned char*)malloc(20);
            int replace_flag = 0;

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
                    too_small = 1;

                }
            }

            if(i < pay_len && !too_small)
            {		
                if(!flag)	//this is done once first time when the first hash is being entered.
			{		
                    flag = 1;
                    if (map_insert_regular_or_feedback(regular,(void*)sha1,(void*)(store_marks[i] - last_mark),status)!=0) 
                    {
                        fprintf(stderr, "entry failed\n");
                        exit(EXIT_FAILURE);
                    }
                }
                else
                {
			int temp = store_marks[i]-last_mark;
			  // 1 - regular  //2 - feedback
			regular_hash = map_insert_regular_or_feedback(regular,(void*)sha1,(void*)(store_marks[i] - last_mark),1);	
			feedback_hash = internal_search(feedback,(void*)sha1,(void*)(store_marks[i] - last_mark),2);
                        if (regular_hash==0 && feedback_hash==0)
                        {
			set_header_hash(store_marks[i]-last_mark);
			
			modify_data_udp[moving_copy++] = status_clear[0]; //pStatusHash or pStatus.
                	modify_data_udp[moving_copy++] = status_clear[1];
			//now insert the length of the file.
			for(k=last_mark;k<store_marks[i];k++){
			modify_data_udp[moving_copy++] = data_udp[k];
			}
                           // fprintf(stderr, "entry failed\n");
                            //exit(EXIT_FAILURE);
                        }
                      else
                      {
			all_original = 0;
			if(regular_hash != 0)
				regular_hit += 1;
			if(feedback_hash != 0)
				feedback_hit += 1;
			int new_packet = 1;
			//set_header();
			set_header_hash(20);
			modify_data_udp[moving_copy++] = status_hash[0];
                	modify_data_udp[moving_copy++] = status_hash[1];
			if(regular_hash != 0 || feedback_hash != 0)
				{
				//sha1 = regular_hash;
                		for(k=0;k<20;k++)
                		{
                    		modify_data_udp[moving_copy++] = sha1[k];
                    		
                		}
				replace_flag = 1;
					}

            	if(replace_flag)
            	{		
                	newRet += 22;  
            	}	
            	else
            	{
                	newRet += (store_marks[i] - last_mark) + 2;
            	}	
		

			//unsigned char *modify_data_udp;	
                
            		

            //if(i<j)
              //  last_mark = store_marks[i];

			
			//compress_packet(packet_data,regular_hash,feedback_hash,0);
                        all_original = 0;
			//totalR += store_marks[i]-last_mark;
                    }	//else for NULL of hashes
                }//else for if flag
                    
            }// if paylen


            if(i<j)
                last_mark = store_marks[i];

        }
ret = 1;
if(all_original ==0)
{
	if(ret == 1)
			{
            		ip_hdr->ip_p = MIXED;
            		newRet = moving_copy;
            		newRet += size_ip;

        		if(VERBOSE1)
            		printf("====== moving_copy %d ==== newRet %d===",moving_copy,newRet);

        		ip_hdr->ip_len = htons(newRet);
        		ip_hdr->ip_sum = in_cksum((unsigned short *) ip_hdr,sizeof(struct ip));

    			*newSize = newRet;
			}
for(k=0;k<moving_copy;k++)
{
data_udp[k] = modify_data_udp[k]; //waht about the tail of the data_udp pointer..there could be data there.
}

}
	return id;  //no change in the packet at all.

}


//include this code inside the else part where the function is called. remove this function or if needed then pass and initialize variables which are there in the print_pkt function.

	
            //data_udp = modify_data_udp;



static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{

    char *send_data;
    int i,newSize;
    struct timeval tim;
    gettimeofday(&tim,NULL);
    double t1 = tim.tv_sec + (tim.tv_usec/1000000.0);

    u_int32_t id = print_pkt(nfa, &newSize,1);

    gettimeofday(&tim,NULL);
    double t2 = tim.tv_sec + (tim.tv_usec/1000000.0);
    total_time = total_time + (t2-t1);
    printf("\n===========================\n");
    printf("Time elapsed so far = %.61f sec \n Average time per packet = %.61f sec \n",total_time,total_time/(float)id);
    printf("Number that makes more sense = %f packets/sec", (float)id/total_time);
    printf("\n===========================\n");
    i = nfq_get_payload(nfa,&send_data);
    printf("entering callback\n ---- newRet : %d %d \n \n",newSize,i);
    return nfq_set_verdict(qh, id, NF_ACCEPT, newSize, (unsigned char *)send_data);


//make a hash array or something and insert bits before segements of corresponding data.
//call fucntion s to compress packets bases on the hits found.
}

static int cb_advertised_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{

    char *send_data;
    int i,newSize;
    struct timeval tim;
    gettimeofday(&tim,NULL);
    double t1 = tim.tv_sec + (tim.tv_usec/1000000.0);

    u_int32_t id = packet_advertised(nfa, &newSize,1);

    gettimeofday(&tim,NULL);
    double t2 = tim.tv_sec + (tim.tv_usec/1000000.0);
    total_time = total_time + (t2-t1);
    printf("\n===========================\n");
    printf("Time elapsed so far = %.61f sec \n Average time per packet = %.61f sec \n",total_time,total_time/(float)id);
    printf("Number that makes more sense = %f packets/sec", (float)id/total_time);
    printf("\n===========================\n");
    i = nfq_get_payload(nfa,&send_data);
    printf("entering callback\n ---- newRet : %d %d \n \n",newSize,i);
    return nfq_set_verdict(qh, id, NF_ACCEPT, newSize, (unsigned char *)send_data);


//make a hash array or something and insert bits before segements of corresponding data.
//call fucntion s to compress packets bases on the hits found.
}


int main(int argc, char **argv)
{


    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    flag = 0;
     initialize_hashTable(); 
    initialize_rabin();
    initializeHashHeader();

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
   //initializtion was here

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

    exit(0);


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
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h1, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        //exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h1, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '1'\n");
    qh = nfq_create_queue(h1,  2, &cb_advertised_packet, NULL);
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

