#include<stdio.h>
#include"scanner.h"
#include<unistd.h>

#define SCAN_TASK 1
int start_processes(int task){
    
}
void worker(int task){
 switch(task){
     case SCAN_TASK:
	     int start,end;
	     printf("Start=");
	     if(scanf("%d",&start)<0)break;
	     printf("End=");
	     if(scanf("%d",&end)<0)break;
	     hostname="127.0.0.1";

	     break;
 }
}
int main(){
   return 0;
}
