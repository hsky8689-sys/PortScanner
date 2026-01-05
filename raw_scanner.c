#include "raw_scanner.h"
int scan_result(struct scan_info data){
	int result = -1;
}
void* scan(void* arg){
        
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
	const char* scan_type = argv[3];
	int maxc = (argc >= 6) ? atoi(argv[5]) : DEFAULT_MAX_CONCURRENT;
	int timeout_ms = (argc >= 7) ? atoi(argv[6]) : DEFAULT_TIMEOUT;
	current_port=first;
	sockets = calloc(maxc,sizeof(int));
        if(sockets==NULL){
           perror("calloc sockets");
         }
        results = calloc(65365,sizeof(int));
        if(results==NULL){                     /*arimtetica...*/
           perror("calloc results");
	   free(sockets);
	   exit(EXIT_FAILURE);
        }
        scanned = calloc(65365,sizeof(int));
        if(scanned==NULL){
           perror("calloc scanned");
	   free(sockets);
	   free(results);
	   exit(EXIT_FAILURE);
        }
	for(int i=0;i<maxc;i++){
	    sockets[i] = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	    if(sockets[i]<0){
	       perror("socket");
	       break;
	    }
	    struct scan_info* info = malloc(sizeof(scan_info));
	    if(info==NULL){
	       perror("malloc scan_info");
	       continue;
	    }
	    strcpy(info->target_ip,host);
	    strcpy(info->scan_type,scan_type);
	    strcpy(info->timeout_ms,timeout_ms);
	    if(pthread_create(&threads[i],NULL,(void*)scan,NULL)<0){
	        perror("pthread_create");
	    }
	}
	for(int i=0;i<maxc;i++){
	     close(sockets[i]);
	     pthread_join(threads[i],NULL);
	}
	for(int i=first;i<=last;i++)
	   fprintf(stdout,"results[%d]=%d,scanned[%d]=%d\n",i,results[i],i,scanned[i]);
	free(sockets);
	free(scanned);
	free(results);
	return 0;
}
