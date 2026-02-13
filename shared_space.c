#include "shared_space.h"
int init_shared_memory(){
    results = mmap(NULL,sizeof(results),
                   PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS,
                   -1,0);
    if(results == MAP_FAILED){
       perror("mmap()");
       return 1;
    }
    return 0; 
}
void write_scan_result(struct parsed_input* parsed){
     printf("__________SCAN_FINISHED_____________");
     printf("PORT NUMBER | STATE | SERVICE | VERSION");
     int filtered = 0;
     int closed = 0;
     
     for(int i=parsed->first;i<=parsed->last;i++){
         if(results->port_states[i]==PORT_FILTERED)
                filtered++;
         if(results->port_states[i]==PORT_CLOSED)
                              closed++;
         }
    
     for(int i=parsed->first;i<=parsed->last;i++){
        if(results->port_states[i]==PORT_OPENED)
                printf(" %d  | OPENED | %s | %s \n",i
                         ,results->services[i]
                         ,results->versions[i]);
        if(results->port_states[i]==PORT_FILTERED
           && filtered >= closed)
                printf(" %d  | FILTERED | %s | %s \n",i
                    ,results->services[i]
                    ,results->versions[i]);
         if(results->port_states[i]==PORT_CLOSED
            && filtered < closed)
                printf(" %d  | CLOSED | %s | %s \n",i
                ,results->services[i]
                ,results->versions[i]);
         }
         if(filtered>=closed)
              printf("%d filtered ports(not shown)\n",filtered);
         else printf("%d closed ports(not shown)\n",closed);
}
void deallocate_shared_memory(){
     if(munmap(results,sizeof(scan_results_t)) == -1)
                          perror("munmap");
     results = NULL;
}
