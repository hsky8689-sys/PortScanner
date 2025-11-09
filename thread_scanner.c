#include<stdio.h>
#include<pthread.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/param.h>
pthread_mutex_t mtx;
typedef struct {
  int first,last;
}range_t;
#define PORTS_PER_THREAD 200
#define MAX_THREADS 600
range_t* compute_ranges(int start,int end){
   int needed = (end - start + 1)/PORTS_PER_THREAD;
   range_t* range = malloc(needed*sizeof(range_t));
   if(range==NULL)return range;
   for(int i=0;i<needed;i++){
       range[i].first=MAX(i*PORTS_PER_THREAD,start);
       range[i].last=MIN((i+1)*PORTS_PER_THREAD,end);
   }
   return range;
}
void* port_scan(void* arg){
     
}
int main(int argc,char** argv){
        if(argc<4){
	   perror("./thread_scanner host start");
	   exit(1);
	}
 	return 0;
}
