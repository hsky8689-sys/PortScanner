#include"process_management.h"

pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
void* calculate_processes(void* arg){
    struct parsed_input inp = *(struct parsed_input*)arg;
    int first = inp.first;
    int last = inp.last;
    
    pthread_mutex_lock(&mutex);
    processes_needed = (last-first+1)/3000;
    if((last-first+1)%3000)processes_needed++;
    pthread_mutex_unlock(&mutex);

    return NULL;
}
void create_scan_processes(int how_many){
   int first = parsed->first;
   int last = parsed->last;
   fprintf(stdout,"Scanning ports %d-%d\n",first,last);
   char* type_requested = parsed->type_scan; 
   {
	   fprintf(stdout,"HOSTNAME:%s\nSCAN TYPE:%s\nSTARTING PORT:%d\nFINAL PORT:%d\n%d\n %d\n",parsed->hostname,
	          parsed->type_scan,parsed->first,parsed->last,parsed->max_concurrent,parsed->timeout);
   }
   
   if(strcmp(type_requested,"-tcp")==0){
        fprintf(stdout,"Starting TCP SCAN...\n");
               while(first<=last){
                	int nexthop = first + 10000;
                	if(nexthop > last) nexthop = last;
                	char cmd[256];
                	snprintf(cmd,sizeof(cmd),"./tcp_scanner %s %d %d %d %d",parsed->hostname,first,nexthop,parsed->max_concurrent,parsed->timeout);
                	system(cmd);
                	first = nexthop + 1;
   		}
	
   }
   else if(strcmp(type_requested,"-udp")==0){
       //TODO 
   }
   else if(strcmp(type_requested,"-syn")==0){
       for(int i=0;i<processes_needed;i++){
          pid_t forc = fork();
	  if(forc<0){
	     perror("fork");
	     _exit(1);
	  }
	  if(forc == 0){
	     char command[MAX_CHARACTERS];
	     int start = MAX(1,i * 3000);
	     int nexthop = MIN(65356,parsed->last);
	     snprintf(command,sizeof(command),"sudo ./raw_scanner %s %d %d %d %d",parsed->hostname,start,nexthop,parsed->max_concurrent,parsed->timeout);
	     system(command);
	     _exit(0);
 	  }
	  sleep(2);
        }
   }
   else if(strcmp(type_requested,"-fyn")==0){
       //TODO
   }
   else if(strcmp(type_requested,"-xmas")==0){
       //TODO
   }
   else if(strcmp(type_requested,"-null")==0){
       //TODO
   }


}
void worker(int task_id){
    fprintf(stdout,"Requesting task type %d\n",task_id);
    switch(task_id)
    {
	    case task_scan:{
	       fprintf(stdout,"TASK SCAN BEING EXECUTED...\n");
               pthread_t tid;
	       pthread_create(&tid,NULL,calculate_processes,(void*)parsed);
	       pthread_join(tid,NULL);
	       fprintf(stdout,"Using %d processes for this scan\n",processes_needed);
	       create_scan_processes(processes_needed);
	       break;
	    }
	    case task_read:{
	       fgets(command,sizeof(command),stdin);
	       command[strlen(command)-1]=0;
	       if(strcmp(command,"exit")==0){
	          worker(task_exit);
	       }
	       fprintf(stdout,"%s %ld\n",command,strlen(command));
	       void *result = (void*)parse(command);
	       if(result){
	           fprintf(stdout,"Result is not null\n");
		   parsed = (struct parsed_input*)result;
	       }
	       else fprintf(stdout,"Result is null\n");
	       break;
	    }
	    case task_write:{
	          break;
	    }
	    case task_exit:{
	       fprintf(stdout,"Closing scanner...Goodbye\n");
	       sleep(2);
	       _exit(0);
	    }
    }
}
int main(){
   worker(task_read);
   worker(parsed->command_type);
   if(parsed)free(parsed);
   return 0;
}
