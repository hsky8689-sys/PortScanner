#include"process_management.h"
void worker(int task_id){
    int processes_needed = 0;
    switch(task_id)
    {
	    case task_read:{
	       command[0]=0;
	       fgets(command,sizeof(command),stdin);
	       //parsed=parse(command);
	       //free(parsed);//!!
	       break;
	    }
	    case task_exit:{
	       fprintf(stdout,"Closing scanner...Goodbye\n");
	       usleep(200);
	       _exit(0);
	    }
    }
}
void menu(){
   int is_running = 1;
   while(1){
   int command;
   fprintf(stdout,"%s",display_text);
   //scanf("%d",&command);
   worker(task_read);   
   sleep(2);
   }
}

int main(){
   menu();
   return 0;
}
