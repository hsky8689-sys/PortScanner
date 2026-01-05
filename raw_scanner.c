#include "raw_scanner.h"
void* listener(void* arg){
   while(1){
      
   }
}
void* worker(void* arg){
    struct scan_info = *(struct scan_info*)arg;
    
    free(scan_info);
}
void start_raw_scan(const char* scan_type){
	if(strcmp(scan_type,"fin")==0){
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
            info->index=i;
            strcpy(info->target_ip,host);
            strcpy(info->scan_type,scan_type);
            strcpy(info->timeout_ms,timeout_ms);
            if(pthread_create(&threads[i],NULL,(void*)worker,info)<0){
                perror("pthread_create");
            }
          }

         if(pthread_create(&listener,NULL,(void*)listener,NULL)<0){
               perror("pthread_create_listener");
         }    
	     return;
	}
	raw_sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
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
	
	raw_scan = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(raw_scan < 0){
	   perror("pthread_create raw socket");
	}
	
	for(int i=0;i<maxc;i++){
	    struct scan_info* info = malloc(sizeof(scan_info));
            if(info==NULL){
               perror("malloc scan_info");
               continue;
            }
            info->index=i;
            strcpy(info->target_ip,host);
            strcpy(info->scan_type,scan_type);
            strcpy(info->timeout_ms,timeout_ms);
            if(pthread_create(&threads[i],NULL,(void*)worker,info)<0){
                perror("pthread_create");
            }
	}
	if(pthread_create(&listener,NULL,(void*)listener,NULL)<0){
	    perror("pthread_create_listener");
	}
	
	for(int i=0;i<maxc;i++){
	     pthread_join(threads[i],NULL);
	}
	
	pthread_join(listener,NULL);
	
	for(int i=first;i<=last;i++)
	   fprintf(stdout,"results[%d]=%d,scanned[%d]=%d\n",i,results[i],i,scanned[i]);
	
	close(raw_scan);
	if(sockets)free(sockets);
	free(scanned);
	free(results);
	return 0;
}
