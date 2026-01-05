#include "raw_scanner.h"
int raw_sock;
void* listener(void* arg){
   char buffer[65535];
   struct sockaddr_in saddr;
   socklen_t saddr_len = sizeof(saddr);

   while(1){
    int size = recvfrom(raw_sock,buffer,65535,0,(struct sockaddr*)&saddr,&saddr_len);
    if(size<0)continue;

    struct iphdr* iph = (struct iphdr*) buffer;

    struct tcphdr* tcph = (struct tcphdr*)(buffer + (iph->ihl*4));
    int source_port = ntohs(tcph->source);
    if(tcph->syn && tcph->ack)
	    results[source_port] = 1;
    else results[source_port] = 2;
   }
   return NULL;
}
void* worker(void* arg){
    struct scan_info* info = (struct scan_info*)arg;
     
    free(info);
}
int main(int argc,char** argv)
{
	if(argc<5){
	   fprintf(stdout,"Usage ./raw_scanner <host> <first port> <last port> <scan_type> [max concurrent] [timeout]\n");
	   return -1;
	}
	if(geteuid()!=0){
           fprintf(stdout,"RAW SCAN REQUIRES ROOT PRIVILEGES\n");
           exit(EXIT_FAILURE);
        }
	const char* host = argv[1];
	first = atoi(argv[2]);
	last = atoi(argv[3]);
	const char* scan_type = argv[4];
	maxc = (argc >= 6) ? atoi(argv[5]) : DEFAULT_MAX_CONCURRENT;
	timeout_ms = (argc >= 7) ? atoi(argv[6]) : DEFAULT_TIMEOUT;
	current_port=first;
	
        results = calloc(65365,sizeof(int));
        if(results==NULL){                     
           perror("calloc results");
	   exit(EXIT_FAILURE);
        }
        scanned = calloc(65365,sizeof(int));
        if(scanned==NULL){
           perror("calloc scanned");
	   free(results);
	   exit(EXIT_FAILURE);
        }
	//one raw socket needed
	raw_scan = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(raw_scan < 0){
	   perror("pthread_create raw socket");
	   free(results);
	   free(scanned);
	   return -EXIT_FAILURE;
	}
	
	for(int i=0;i<maxc;i++){
	    struct scan_info* info = malloc(sizeof(struct scan_info));
            if(info==NULL){
               perror("malloc scan_info");
               continue;
            }
            info->index=i;
            strcpy(info->target_ip,host);
            strcpy(info->scan_type,scan_type);
            info->timeout_ms=timeout_ms;
            if(pthread_create(&threads[i],NULL,(void*)worker,info)<0){
                perror("pthread_create");
            }
	}

	if(pthread_create(&listener_thread,NULL,(void*)listener,NULL)<0){
	    perror("pthread_create_listener");
	}
	
	for(int i=0;i<maxc;i++){
	     pthread_join(threads[i],NULL);
	}
	
	pthread_join(listener_thread,NULL);
	
	for(int i=first;i<=last;i++)
	   fprintf(stdout,"results[%d]=%d,scanned[%d]=%d\n",i,results[i],i,scanned[i]);
	
	close(raw_scan);
	free(scanned);
	free(results);
	return 0;
}
