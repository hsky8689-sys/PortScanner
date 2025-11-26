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
   for(int i=0;i<how_many;i++){
      pid_t forc = fork();
      if(forc<0){perror("fork");return;}
      if(forc==0){
         int start = MAX(i*MAX_FD_PER_PROCESS,first); 
         int end = MIN((i+1)*MAX_FD_PER_PROCESS,last);
	 if(strcmp(parsed->type_scan,"-tcp")==0){
	     char c_start[12];
	     char c_end[12];
	     char c_maxc[12];
	     char c_timeout[12];

	     snprintf(c_start,sizeof(c_start),"%d",start);
	     snprintf(c_end,sizeof(c_end),"%d",end);
	     snprintf(c_maxc,sizeof(c_maxc),"%d",parsed->max_concurrent);
	     snprintf(c_timeout,sizeof(c_timeout),"%d",parsed->timeout);

	     execlp("./tcp_scanner","tcp_scanner",parsed->hostname,c_start,c_end,c_maxc,c_timeout,NULL);
             fprintf(stdout,"This shouldn't appear..\n");
	 }
	 exit(0);
      }
      else wait(NULL);
   }
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
