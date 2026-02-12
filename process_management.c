#include"process_management.h"

pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
void* run_sniffer(void* arg){
     worker(task_sniff);
}
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
                	snprintf(cmd,sizeof(cmd),"./tcp_scanner %s %d %d %d %d",parsed->hostname,1,2,parsed->max_concurrent,parsed->timeout);
                	system(cmd);
                	first = nexthop + 1;
   		}
	
   }
   else if(strcmp(type_requested,"-udp")==0){
       //TODO 
   }
   else if(strcmp(type_requested,"-syn")==0){
	snprintf(command,sizeof(command),"sudo ./raw_scanner %s %d %d %d %d",parsed->hostname,parsed->first,parsed->last,parsed->max_concurrent,parsed->timeout);
        for(int i=0;i<DEFAULT_RETRY;i++){
	     system(command);
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
	       pid_t sniffer_pid = fork();
	       if(sniffer_pid < 0){
	           perror("sniffer fork()");
		   _exit(1);
	       }
	       if(sniffer_pid == 0){
	          freopen("sniffer_output.txt","w",stdout);
		  freopen("sniffer_errors.txt","w",stderr);

		  setvbuf(stdout,NULL,_IONBF,0);

		  setup_sniffer(parsed->hostname,"eth0");
		  _exit(0);
	       }
	       else{
		       sleep(3);
		       create_scan_processes(67);
		       sleep(5);
		       kill(sniffer_pid,SIGTERM);
		       waitpid(sniffer_pid,NULL,0);

	       }
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
	    case task_sniff:{
	          setup_sniffer(parsed->hostname,"eth0");
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
