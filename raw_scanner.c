#include "raw_scanner.h"
int raw_sock;
int listen_responses;
char source_ip[16];
char target_ip[16];
//uint32_t cookie;
int closed;
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
      
      unsigned short iphdrlen = iph->ihl*4;
      struct tcphdr *tcph = (struct tcphdr*)(buffer+ iphdrlen);

      if(iph->saddr != inet_addr(target_ip))continue;

      uint32_t received_ack = ntohl(tcph->ack_seq);
      uint32_t ip_src_int = iph->saddr;
      uint16_t port_src_int = tcph->source;
      uint16_t port_dst_int = tcph->dest;

      uint32_t expected_seq = cookie+ip_src_int+port_src_int+port_dst_int;

      if(received_ack == expected_seq + 1){
	      int source_port = ntohs(port_src_int);
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
			   usleep(100);
			   break;
		    }
	    }
	    usleep(50000);
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
	if(maxc > DEFAULT_MAX_CONCURRENT)maxc = DEFAULT_MAX_CONCURRENT;

	int sys_max = get_max_threads_allowed();
	printf("System allows maximum %d processes/threads \n", sys_max);
	
	if(maxc > sys_max * 0.8){
	   maxc = sys_max * 0.8;
	   printf("Adjusted max nr of threads (%d) for stability\n",maxc);
	}

	
	timeout_ms = (argc >= 7) ? atoi(argv[6]) : DEFAULT_TIMEOUT;

	listen_responses = 1;

        results = calloc(65355,sizeof(int));
        if(results==NULL){                     
           perror("calloc results");
	   exit(EXIT_FAILURE);
        }
        scanned = calloc(65355,sizeof(int));
        if(scanned==NULL){
           perror("calloc scanned");
	   free(results);
	   exit(EXIT_FAILURE);
        }
	//one raw socket needed
	
	raw_sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(raw_sock < 0){
	   perror("socket()");
	   free(results);
	   free(scanned);
	   exit(EXIT_FAILURE);
	}

	srand(time(NULL));
	cookie = rand() % 0xFFFFFFFF;

	int one = 1;
	int rcvbuffer = 4*1024*1024;
	if(setsockopt(raw_sock,SOL_SOCKET,SO_RCVBUF,&rcvbuffer,sizeof(rcvbuffer))<0){
	    perror("setsockopt1\n");
	}

        if(setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))<0){
	perror("setsockopt2\n");
	}

	struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100* timeout_ms;
        setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	
	pthread_attr_t attributes;
	pthread_attr_init(&attributes);

	pthread_attr_setstacksize(&attributes,1024*1024);
	
	current_port=first;
	{

/*		if(pthread_create(&listener_thread,&attributes,(void*)listener,NULL)<0){
            	perror("pthread_create_listener");
        	}
*/
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
  //      	pthread_join(listener_thread,NULL);
	        
	}
//	
	for(int i=first;i<=last;i++)
	  if(results[i]==0);
		  //fprintf(stdout,"Port %d filtered\n",i);
	  else if(results[i]==1);
		  //fprintf(stdout,"Port %d open\n",i);
	  else if(results[i]==2);
		  //closed++;
	//fprintf(stdout,"%d ports closed(RST received)\n",closed);
	close(raw_sock);
	free(scanned);
	free(results);
	return 0;
}
