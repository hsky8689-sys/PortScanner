#include "raw_scanner.h"
int raw_sock;
int listen_responses;

void* listener(void* arg){
   char buffer[65535];
   struct sockaddr_in saddr;
   socklen_t saddr_len = sizeof(saddr);
 
   fprintf(stdout,"Listening for responses...\n");
   while(current_port<=last){
    int size = recvfrom(raw_sock,buffer,65535,0,(struct sockaddr*)&saddr,&saddr_len);
    if(size<0)continue;
    fprintf(stdout,"Received %d bytes of data\n",size);
    struct iphdr* iph = (struct iphdr*) buffer;

    struct tcphdr* tcph = (struct tcphdr*)(buffer + (iph->ihl*4));
    int source_port = ntohs(tcph->source);
    if(tcph->syn && tcph->ack)
	    results[source_port] = 1;
    else results[source_port] = 2;
   }
   fprintf(stdout,"Listener closed\n");
   return NULL;
}
void* worker(void* arg){
    struct scan_info* info = (struct scan_info*)arg;

    while(1){
	    info->port = current_port;
	    if(scanned[current_port]){
	        continue;
	    }
	    pthread_mutex_lock(&mutex);
	    if(current_port > last){
                pthread_mutex_unlock(&mutex);
                break;
            }
	    //int result = raw_scan(raw_sock,info);
	    if(raw_scan(raw_sock,info)>0)
		 scanned[current_port] = 1;
	    current_port++;
	    pthread_mutex_unlock(&mutex);

	    usleep(100);
    }
skip:
    free(info);
    return NULL;
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
	char target_ip[16];
	char my_ip[20];
        get_machine_ip(my_ip);
	
	if(inet_addr(host) == INADDR_NONE){
		if(resolve_hostname(host,target_ip)!=0){
		    fprintf(stderr,"Could not resolve hostname");
		    return -1;
		}
		printf("Found IP: %s\n",target_ip);
	}
	else strcpy(target_ip,host);
          
	first = atoi(argv[2]);
	last = atoi(argv[3]);
	const char* scan_type = argv[4];
	maxc = (argc >= 6) ? atoi(argv[5]) : DEFAULT_MAX_CONCURRENT;
	timeout_ms = (argc >= 7) ? atoi(argv[6]) : DEFAULT_TIMEOUT;
	current_port=first;
	listen_responses = 1;

        results = calloc(65536,sizeof(int));
        if(results==NULL){                     
           perror("calloc results");
	   exit(EXIT_FAILURE);
        }
        scanned = calloc(65536,sizeof(int));
        if(scanned==NULL){
           perror("calloc scanned");
	   free(results);
	   exit(EXIT_FAILURE);
        }
	//one raw socket needed
	raw_sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(raw_sock < 0){
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
	    info->target_ip = malloc(40*sizeof(char));
	    if(info->target_ip==NULL){
	       perror("malloc target ip");
	       continue;
	    }
	    info->scan_type = malloc(40*sizeof(char));
	    if(info->scan_type==NULL){
	       perror("malloc scan type");
	       continue;
            }
            info->index=i;
            strcpy(info->target_ip,target_ip);
            strcpy(info->scan_type,scan_type);
            info->timeout_ms=timeout_ms;
            
	    if(pthread_create(&threads[i],NULL,(void*)worker,info)<0){
                perror("pthread_create");
                free(info);
	    }
	}

        
	if(pthread_create(&listener_thread,NULL,(void*)listener,NULL)<0){
	    perror("pthread_create_listener");
	}
	
	for(int i=0;i<maxc;i++){
	     pthread_join(threads[i],NULL);
	}
	listen_responses = 0;
	
	pthread_join(listener_thread,NULL);
	
	for(int i=first;i<=last;i++)
	  if(results[i]>-1)
	    fprintf(stdout,"results[%d]=%d,scanned[%d]=%d\n",i,results[i],i,scanned[i]);
	
	close(raw_sock);
	free(scanned);
	free(results);
	return 0;
}
