#include"process_management.h"

void create_scan_processes(){
   int first = parsed->first;
   int last = parsed->last;
   fprintf(stdout,"Scanning ports %d-%d\n",first,last);
   char* type_requested = parsed->type_scan; 
   
   {
	   fprintf(stdout,"HOSTNAME:%s\nSCAN TYPE:%s\nSTARTING PORT:%d\nFINAL PORT:%d\n%d\n %d\n",parsed->hostname,
	          parsed->type_scan,parsed->first,parsed->last,parsed->max_concurrent,parsed->timeout);
   }
   
   if(strcmp(type_requested,"-tcp")==0){
                	snprintf(command,sizeof(command),
				"./tcp_scanner %s %d %d %d %d",
				parsed->hostname,parsed->first,
				parsed->last,parsed->max_concurrent
				,parsed->timeout);
   }
   else if(strcmp(type_requested,"-udp")==0){
       			snprintf(command,sizeof(command),
                                "sudo ./udp_scanner %s %d %d %d %d",
                                parsed->hostname,parsed->first,
                                parsed->last,parsed->max_concurrent
                                ,parsed->timeout);
   }
   else if(strcmp(type_requested,"-syn")==0 || strcmp(type_requested,"-fyn")==0 || strcmp(type_requested,"-null")==0 || strcmp(type_requested,"xmas")==0){
	strcpy(type_requested,type_requested+1);
	snprintf(command,sizeof(command),"sudo ./raw_scanner %s %d %d %s %d %d",parsed->hostname,parsed->first,parsed->last,type_requested,parsed->max_concurrent,parsed->timeout);
        for(int i=0;i<DEFAULT_RETRY;i++){
	     system(command);
        }
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
		  setvbuf(stdout, NULL, _IONBF, 0);
        	  setvbuf(stderr, NULL, _IONBF, 0);
        
		  setup_sniffer(parsed->hostname,"eth0");
		  _exit(0);
	       }
	       else{
	          sleep(2);
		  create_scan_processes();
		  sleep(5);
		  kill(sniffer_pid,SIGTERM);
		  waitpid(sniffer_pid,NULL,0);
		  worker(task_write);
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
		  if(init_shared_memory()<0){
		  	perror("mmap init\n");
			break;
		  }
	          setup_sniffer(parsed->hostname,"eth0");
		  break;
	    }
	    case task_write:{
		  write_scan_result(parsed);
		  deallocate_shared_memory();
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
