#include"process_management.h"
pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
void* calculate_processes(void* arg){
    struct parsed_input inp = *(struct parsed_input*)arg;
    int first = inp.first;
    int last = inp.last;
    
    pthread_mutex_lock(&mutex);
    processes_needed = (last-first+1)/MAX_FD_PER_PROCESS;
    if((last-first+1)%MAX_FD_PER_PROCESS)processes_needed++;
    pthread_mutex_unlock(&mutex);

    return NULL;
}
void create_scan_processes(int how_many){
   int first = parsed->first;
   int last = parsed->last;
   fprintf(stdout,"Scanning ports %d-%d\n",first,last);
   const char* type_requested = (char*)&parsed->scan_type; 
   	fprintf(stdout,"type %s\n",type_requested);
        //if(strcmp(type_requested,"syn")==0){
{
   	while(first <= last){
        	int nexthop = first + 1000;
        	if(nexthop > last) last = nexthop;
		char cmd[256];
		snprintf(cmd,sizeof(cmd),"sudo ./raw_scanner %s %d %d %s %d %d | grep -E open","cs.ubbcluj.ro",first,nexthop,"syn"/*parsed->type_scan*/,parsed->max_concurrent,parsed->timeout);
		system(cmd);
		first = nexthop + 1;	
   	}
   }
	//else fprintf(stdout,"Le fac maine ... \n");
}
void worker(int task_id){
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
	       void* result = (void*)parse(command);
	       if(result){
	           fprintf(stdout,"Result is not null\n");
		   parsed=(struct parsed_input*)result;
	           free(result);
	       }
	       else fprintf(stdout,"Result is null\n");
	       break;
	    }
	    case task_exit:{
	       fprintf(stdout,"Closing scanner...Goodbye\n");
	       sleep(2);
	       _exit(0);
	    }
    }
}
void menu(){
   int is_running = 1;
   while(1){
   worker(task_read);
   if(parsed){worker(parsed->command_type);
   
	   fprintf(stdout,"'parsed' freed...\n");
   }   
   sleep(2);
   }
}

int main(){
   menu();
   return 0;
}
