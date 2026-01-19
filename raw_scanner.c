#include "raw_scanner.h"
int raw_sock;
int listen_responses;
char source_ip[16];
char target_ip[16];
int validare_pachet(unsigned char* buffer, uint32_t expected_ack, uint32_t target_ip) {
    return 0;
}
void* listener(void* arg){
   char buffer[65535];
   struct sockaddr_in saddr;
   socklen_t saddr_len = sizeof(saddr);
 
   while(listen_responses){
      int size = recvfrom(raw_sock,buffer,65535,0,(struct sockaddr*)&saddr,&saddr_len);

      if(size<0){
          if(errno == EAGAIN || errno == EWOULDBLOCK){
	     usleep(1000);
	     continue;
	  }
	  fprintf(stderr,"Recvfrom error %s",strerror(errno));
	  break;
      }
      
      struct iphdr *iph = (struct iphdr*)buffer;
      if(iph->protocol!=IPPROTO_TCP)continue;

      unsigned short iphdrlen = iph->ihl*4;
      struct tcphdr *tcph = (struct tcphdr*)(buffer+ iphdrlen);

      int source_port = ntohs(tcph->source);
      int dest_port = ntohs(tcph->dest);

      if(dest_port == 12345){

      if(source_port>=first && source_port <=last && !scanned[source_port]){
         
	  scanned[source_port] = 1;
	  if (tcph->syn && tcph->ack) {
                    results[source_port] = 1;
                }
                else if (tcph->rst) {
                    results[source_port] = 2;
                }
	        
         }
      }
   }
   return NULL;
}
void* worker(void* arg){
    struct scan_info* info = (struct scan_info*)arg;

    while(1){
	    int port_to_scan = -1;

	    pthread_mutex_lock(&mutex);
	    if(current_port <= last){
                port_to_scan = current_port++;
		info->port = port_to_scan;
            } 
	    pthread_mutex_unlock(&mutex);
	    if(port_to_scan == -1)break;

	    if(raw_scan(raw_sock,source_ip,info)<0){
		    perror("plange raw scanu\n");
		    switch(errno){
		      case EINVAL:
			   printf("Date prost initializate\n");
			   break;
		      case EFAULT:
			   printf("dest sau datagram proaste\n");
			   break;
		      default:
			   printf("errno=%d\n",errno);
			   break;
		    }
	    }
	    usleep(5000);
    }
    free(info->target_ip);
    free(info->scan_type);
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


        get_machine_ip(source_ip);
	if(!source_ip[0]){
	   perror("Could not retrieve machine ip\n");
	   return -EXIT_FAILURE;
	}

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
	
	int sys_max = get_max_threads_allowed();
	printf("System allows maximum %d processes/threads \n", sys_max);
	
	if(maxc > sys_max * 0.8){
	   maxc = sys_max * 0.8;
	   printf("Adjusted max nr of threads (%d) for stability\n",maxc);
	}

	
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
	
	int one = 1;

        setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

	struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = timeout_ms;
        setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	
	if(raw_sock < 0){
	   perror("pthread_create raw socket");
	   free(results);
	   free(scanned);
	   return -EXIT_FAILURE;
	}
	
	pthread_attr_t attributes;
	pthread_attr_init(&attributes);

	pthread_attr_setstacksize(&attributes,1024*1024);

	if(pthread_create(&listener_thread,&attributes,(void*)listener,NULL)<0){
            perror("pthread_create_listener");
        }

	listen_responses = 1;
	for(int i=0;i<maxc;i++){
	    struct scan_info* info = malloc(sizeof(struct scan_info));
            if(info==NULL){
               perror("malloc scan_info");
               continue;
            }
	    info->target_ip = malloc(40*sizeof(char));
	    if(info->target_ip==NULL){
	       perror("malloc target ip");
	       free(info);
	       continue;
	    }
	    info->scan_type = malloc(40*sizeof(char));
	    if(info->scan_type==NULL){
	       perror("malloc scan type");
	       free(info);
	       continue;
            }
            info->index=i;
            strcpy(info->target_ip,target_ip);
            strcpy(info->scan_type,scan_type);
            info->timeout_ms=timeout_ms;
            
	    if(pthread_create(&threads[i],&attributes,(void*)worker,info)<0){
                perror("pthread_create");
                free(info);
	    }
	}
	
	for(int i=0;i<maxc;i++){
	     pthread_join(threads[i],NULL);
	}

	sleep(2);
	listen_responses = 0;
        	
	pthread_join(listener_thread,NULL);
	
	for(int i=first;i<=last;i++)
	  if(!results[i]||!scanned[i]){
	   fprintf(stdout,"Port %d unreachable\n",i);
	   //fprintf(stdout,"results[%d]=%d,scanned[%d]=%d\n",i,results[i],i,scanned[i]);
	
	  }
	  else if(results[i]==1 && scanned[i]==1){
	   fprintf(stdout,"Port %d opened\n",i);
	  }
	  else fprintf(stdout,"Port %d closed|filtered\n",i);

	close(raw_sock);
	free(scanned);
	free(results);
	return 0;
}
