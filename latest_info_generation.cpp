#include <string.h>
#include <iostream>
#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include <map>
#include <utility>

using namespace std;

struct mapid{
int length;
};

typedef struct mapid mapid;
mapid node,node1;

  map<int, map<int , mapid > > cidmap;

	   map<int , map<int , int> > ciddetails;

//0 - size of connection
//1 - interconnection
//2 intra conenciton
//3 overall conneciton
void makethedatastructure(int *array,int length,int lengthlist,int start)
{
int flag =0,k=0;
int *uniqueid;
uniqueid = (int*)malloc(lengthlist*(sizeof(int)));
uniqueid[0] = array[0];
ciddetails[array[0]][0] += length;
if(lengthlist < 2 && ciddetails[array[0]][2] == 0)
cidmap[array[0]][0].length += 0;
int unique_length = 1,found;
int j=1;
k=1;
//printf("length od list %d and lenght of segemnt is%d\n",lengthlist,length);
while(k < lengthlist)
{
flag=0,found=0;
int i;


j=unique_length;
for(i=0;i<unique_length;i++)
{
//if(j>1) // this if loop has been added thats it
cidmap[array[k]][uniqueid[i]].length +=length;
if(array[k]==uniqueid[i])
ciddetails[array[k]][2] += length;
if(uniqueid[i] == array[k]){
flag = 1;
}
}



if(!flag){
uniqueid[i] = array[k];
j++;}


if(j>1)
ciddetails[array[k]][1] += length;

unique_length = j;
if(k>0)
ciddetails[array[k]][3] += length;
ciddetails[array[k]][0] += length;
k++;
}
free(uniqueid);
}


void stripnl(char *str) {
  while(strlen(str) && ( (str[strlen(str) - 1] == 13) ||
       ( str[strlen(str) - 1] == 10 ))) {
    str[strlen(str) - 1] = 0;
  }
}
char line[12722222];

int myPow(int x, int p) {
  if (p == 0) return 1;
  if (p == 1) return x;
  return x * myPow(x, p-1);
}


int main(int argc,char *argv[])
{
//map<int , int> hashcounter;
char ln[1000];
FILE *f,*fp;

f = fopen (argv[1], "r");

int index=0;

int counter = 0,start=1;

while(fgets(line,sizeof(line),f)!=NULL)
{
        counter++;
        if(counter%10000==0)
	printf("counter %d\n",counter);
	if(counter > 40700000)
	printf("counter actual is %d",counter);
        //printf("one\n");
        int d=0,k=0,i=0,temp=0;
       //printf("%s\n",line);
        stripnl(line);
        int len = strlen(line);
        //printf("lengthis %d\n",len);
        int check=0,length=0,all=0,list[len],lenarr[10];
        int *array = (int*)malloc(len*(sizeof(int)));
        if(array == NULL)
                exit(-1);
                //printf("length%d\n",len);
        while((line[check]) != '='){
        lenarr[d] = (int)line[check] - 48;
        d++;
        check++;}
                k=0;
                if(d > 1){
                        d--;
                        while(d>=0){
                   length += lenarr[k]*(myPow(10,d));
                        //printf("temp is%d",temp);
                        d--;
                        k++;
                        }}
                        else
                        length = lenarr[0];
        //printf("lengthis%d\n",length);
        d=0,k=0;
        i = check+1;
        while(i<len)
        {temp = 0;
                d=0;
                while(line[i] != '='){
                        array[d] = ((int)line[i]) - 48;
                                d++;
                                i++;
                        }
                if(d>1){
                        d--;
                 while(d>=0){
                   temp += array[k]*(myPow(10,d));

                        d--;
                        k++;
                        }
                k=0;}
                else
                temp = array[0];

                list[all] = temp;
                all++;

                        i++;}
        makethedatastructure(list,length,all,start);
        free(array);
        start = counter;
  //      hashcounter[counter] = length;

}
fclose(f);

int sum=0,total=0;

for( map<int, map<int , mapid > >::iterator ii=cidmap.begin(); ii!=cidmap.end(); ++ii)
   {
	
        cout<<"cid "<<(*ii).first <<" size "<<ciddetails[(*ii).first][0]<<" overall "<<ciddetails[(*ii).first][3]<<" inter "<<ciddetails[(*ii).first][1]<<" intra "<<ciddetails[(*ii).first][2] ;	

map<int, int > hashcount;
	multimap <int , int> newmap;
int cids[40];
        for( map<int , mapid >::iterator xx=((*ii).second).begin(); xx!=((*ii).second).end(); ++xx)
	{     int key,value;
		printf("added cids to multimap %d\n",(*xx).first);
		key = ((*xx).second).length;
		printf("length is %d\n",key);
		newmap.insert(pair<int, int>(key, (*xx).first));

   }
sum=0;
int out=0,x=0,counter=0;
int loop=0;
for( map<int ,int>::iterator gg=--newmap.end(); gg!=newmap.begin(); gg--)
{
loop = 1;
if((*gg).second==(*ii).first)
continue;
cout<<" best "<<(*gg).second;
cout<<" redundant bytes "<<(*gg).first<<endl;
break;
}
if(loop ==0)
cout<<endl;
}

}

