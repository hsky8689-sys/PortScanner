#include "shared_space.h"
scan_results_t* scan_results = NULL;
int init_shared_memory(){
    printf("Initializing IPC memory...\n");
    scan_results = mmap(NULL, sizeof(scan_results_t),  // ~65MB
                       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if(scan_results == MAP_FAILED){
        perror("mmap()");
        return -1;
    }
    printf("Shared mem OK: %p (size: %zu)\n", scan_results, sizeof(scan_results_t));
    memset(scan_results, 0, sizeof(scan_results_t));
    return 0; 
}
void write_scan_result(struct parsed_input* parsed){
     printf("__________SCAN_FINISHED_____________\n");
     printf("PORT NUMBER | STATE | BANNER\n");
     
     int filtered = 0;
     int closed = 0;
     int opened = 0;

     for(int i=parsed->first;i<=parsed->last;i++){
         if(scan_results->port_states[i]==PORT_FILTERED)
                filtered++;
	 else if(scan_results->port_states[i]==PORT_CLOSED)
                              closed++;
	 else if(scan_results->port_states[i]==PORT_OPENED)
		 	      opened++;
     	 }
    
     for(int i=parsed->first;i<=parsed->last;i++){
        if(scan_results->port_states[i]==PORT_OPENED)
                printf(" %d  | OPENED | %s \n",i
                         ,scan_results->banners[i]);
        }
     if(opened>0){
	 int shown = 0;
         if(filtered >= closed){
		 printf("%d filtered ports(not shown)\n",filtered);
	         for(int i = parsed->first; i<=parsed->last && shown<10;i++){
		 	int state = scan_results->port_states[i];
           		char* service = scan_results->services[i];
           		char* version = scan_results->versions[i];
			if(state == 2){
			    printf(" %d  | CLOSED | %s \n",i
                         	,scan_results->banners[i]);
			 	shown++;	
			}
		 
		 }
			 
	 } 
	 else
		 printf("%d closed ports(not shown)\n",closed);
	 	 for(int i = parsed->first; i<=parsed->last && shown<10;i++){
                        int state = scan_results->port_states[i];
                        char* service = scan_results->services[i];
                        char* version = scan_results->versions[i];
                        if(state == 0){
                            printf(" %d  | FILTERED | %s\n",i
                                ,scan_results->banners[i]);
				shown++;
			    }

                 }
     }
     else{
        int shown = 0;
	for(int i = parsed->first ;i<=parsed->last && shown < 10;i++){
	   int state = scan_results->port_states[i];
	   char* service = scan_results->services[i];
	   char* version = scan_results->versions[i];
	   char* banner = scan_results->banners[i];
	   if(state == 2|| state == 0){
	       	   printf("%d | %s | %s",i,state == 2 ? "CLOSED":"FILTERED"
			 ,strlen(banner) > 0 ? banner : "Unknown");
		   shown++;
	   }
	}
     }
}
void deallocate_shared_memory(){
     if(munmap(scan_results,sizeof(scan_results_t)) == -1)
                          perror("munmap");
     scan_results = NULL;
}
