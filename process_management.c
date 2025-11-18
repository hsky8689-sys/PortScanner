#include"process_management.h"
void worker(int task_id){
    int processes_needed = 0;
    switch(task_id){
       case task_show_connections:{
             					  
	     break;
	     }
       case task_scan:{
	   char hostname[50];
           char first[50];
	   char last[65365];
	   fprintf(stdout,"Enter the address:");
	   scanf("%s",hostname);
	   fprintf(stdout,"First port:");
	   scanf("%s",first);
           
	   fprintf(stdout,"Last:port");
	   scanf("%s",last);
	   
	   processes_needed = MAX((atoi(last)-atoi(first)+1) / MAX_FD_PER_PROCESS,1);
	   printf("Using %d processes for this scan\n",processes_needed);
	   for(int i=0;i<processes_needed;i++){
	       pid_t forc = fork();
	       if(forc<0){
	          perror("fork");
		  return ;
	       }
               if(forc==0){
		  char first_port[5];
		  char last_port[5];
		  int start_index = MAX(i*MAX_FD_PER_PROCESS,atoi(first));
		  int end_index = MIN((i+1)*MAX_FD_PER_PROCESS,atoi(last));
	          
		  sprintf(first_port,"%d",start_index);
		  sprintf(last_port,"%d",end_index);

		  printf("Process %d handling ports %s-%s\n",i,first_port,last_port);
		  execlp("./scanner","scanner",hostname,first_port,last_port,"100","10",NULL);
	          _exit(0);
	       }
	   }
	   for(int i=0;i<processes_needed;i++){
	       wait(NULL);
	   }
	   break;
       }
       case 5:{
       fprintf(stdout,"Closing scanner");
       exit(0);
       }
       default:{
	 fprintf(stdout,"Wrong command");     
	 }
   }
}
void menu(){
   int is_running = 1;
   while(is_running){
   //char command[100];
   int command;
   fprintf(stdout,"%s",display_text);
   //fgets(command,100,stdin);
   scanf("%d",&command);
   worker(command);   
   sleep(2);
   }
}

int main(){
   //worker(2);
   menu();
   return 0;
}
