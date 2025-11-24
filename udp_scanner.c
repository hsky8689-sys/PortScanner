#include "udp_scanner.h"
/*
 struct addrinfo {
               int              ai_flags;
               int              ai_family;
               int              ai_socktype;
               int              ai_protocol;
               socklen_t        ai_addrlen;
               struct sockaddr *ai_addr;
               char            *ai_canonname;
               struct addrinfo *ai_next;
           };
 */
int* sockets;
int* results;
int* scanned;
pthread_t threads[1024];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
struct scan_info{
   int index;
   int port;
   int timeout_ms;
   struct addrinfo addr_info;
};
int current_port,first,last;
int scan_result(struct scan_info data){
   int result = -1;
   if(sockets[data.index]<0){
      fprintf(stderr,"Socket no %d got somehow shut down\n",data.index);
      sockets[data.index] = socket(data.addr_info.ai_family,SOCK_DGRAM,0);
   }
   int raw_sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
   if(raw_sock < 0){
      perror("raw socket wasnt created");
      return -2;
   }
   char message[] = "Hello?..";
   socklen_t addrlen = sizeof(data.addr_info);

   sendto(raw_sock,message,strlen(message),0,(struct sockaddr*)&data.addr_info,addrlen);

   struct pollfd pfd[1];
   pfd[0].fd = raw_sock;
   pfd[0].events = POLLIN;

   int ans = poll(pfd,1,data.timeout_ms);
   if(ans == -1)perror("poll");
   else if(ans == 0){
   
   }else if(pfd[0].revents & POLLIN){
      char response[1000];
      if(recvfrom(raw_sock,response,sizeof(response),0,NULL,NULL)>0){
	 struct icmphdr* icmph = (struct icmphdr*)(response + sizeof(struct iphdr));
         if (icmph->type == ICMP_DEST_UNREACH && icmph->code == ICMP_PORT_UNREACH) {
           result = 0;
           printf("Port %d is Closed (ICMP Port Unreachable).\n", data.port);
       } 
           else if (icmph->type == ICMP_DEST_UNREACH && 
             (icmph->code == ICMP_HOST_UNREACH || // 1: Host unreachable
             icmph->code == ICMP_PROT_UNREACH || // 2: Protocol unreachable
             icmph->code == 9 || // Communication Administratively Filtered (Source Quench)
             icmph->code == 10 || // Communication Administratively Prohibited (Host)
             icmph->code == 13) // Communication Administratively Prohibited (Port)) 
		     ){
    result = 2; // 2 = Filtrat
    printf("Port %d is Filtered (ICMP Administratively Prohibited / Host Unreachable).\n", data.port);
}
// 3. Alt Răspuns ICMP (Poate fi o eroare de rutare sau TTL expirat)
else {
    result = 3; // Tratăm orice ICMP care nu e Port Unreachable ca Filtrat/Eroare
    printf("Port %d received unexpected ICMP Type %d, Code %d. Treated as Filtered.\n", data.port, icmph->type, icmph->code);
}  
      }
     else{
	result=1;
        printf("opened|filtered");
     }
   }
   close(raw_sock);
   return result;
}
void* udp_scan(void* arg){ 
    struct scan_info* data = (struct scan_info*)arg; 
    while(1){
         
	 pthread_mutex_lock(&mutex);
         scanned[current_port]=1;
	 current_port++;
         
	 if(scanned[current_port]){//so that we don't scan the same port twice
	    pthread_mutex_unlock(&mutex);
	    continue;
	 }	 
	 pthread_mutex_unlock(&mutex);
         
         if(current_port>=last){
	    break;
	 }
	 data->port=current_port;
	 int res = scan_result(*data);
	 
	 pthread_mutex_lock(&mutex);
	 results[current_port]=res;
	 pthread_mutex_unlock(&mutex);
      }
      free(data);
      return NULL;
}
int main(int argc,char ** argv)
{
     if (argc < 4) {
        fprintf(stderr, "Usage: %s <host> <first_port> <last_port> [max_concurrent] [timeout_ms]\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];
    first = atoi(argv[2]);
    last  = atoi(argv[3]);
    int maxc  = (argc >= 5) ? atoi(argv[4]) : 128;
    int timeout_ms = (argc >= 6) ? atoi(argv[5]) : 500;
    if (first < 1 || last < first || maxc <= 0) { fprintf(stderr,"bad args\n"); return 1; }
    
    sockets = calloc(maxc,sizeof(int));
    if(sockets==NULL){
       perror("calloc sockets");
    }
    results = calloc(60000,sizeof(int));
    if(results==NULL){                     /*arimtetica...*/
       perror("calloc results");
    }
    scanned = calloc(60000,sizeof(int));
    if(scanned==NULL){
       perror("calloc scanned");
    }
    current_port = first;

    for(int i=0;i<maxc;i++){ 
        sockets[i] = socket(AF_INET,SOCK_DGRAM,0);
	if(sockets[i]<0){
	   perror("socket");
	   break;
	}
	
	struct scan_info* info = malloc(sizeof(struct scan_info));

        if(info==NULL){perror("malloc scan_info");continue;}

	info->port = current_port;
	info->timeout_ms = timeout_ms;
	info->index = i;

	if(pthread_create(&threads[i],NULL,(void*)udp_scan,info)<0){
	   perror("pthread");
	}
    }
    for(int i=0;i<maxc;i++){
        close(sockets[i]);
	pthread_join(threads[i],NULL);
    }

    printf("Opened ports:\n");
    for(int i=first;i<last;i++)
	    if(results[i]==1)
		    printf("%d\n",i);
    free(sockets);
    free(results);
    free(scanned);
    return 0;
}
