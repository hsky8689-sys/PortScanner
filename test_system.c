#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include "raw_scanner.h"
int main(){
	/*
    int first = 1;
    int last = 34500;
    const char* target = "193.231.20.20";
    const char* scan_type = "syn";
    int ports_per_scan = 10000;
    while(first <= last){
         int nexthop = first + ports_per_scan;
         if(nexthop>last)nexthop = last;
         char cmd[256];
        snprintf(cmd, sizeof(cmd),
             "./tcp_scanner %s %d %d %d %d",
             "193.231.20.20 ", first, nexthop,100,500);
         system(cmd);
	 sleep(1);
         first = nexthop+1;
    }
    const char* sir = "Nume";
    char* altsir = malloc(10*sizeof(char));
    if(altsir==NULL){
        perror("malloc");
	return -1;
    }
    strncpy(altsir,sir,strlen(sir));
    fprintf(stdout,"Altsir:%s size:%ld",altsir,strlen(altsir));
    */
    char * chr = "-tcp";
    fprintf(stdout,"%s %s %ld",strstr("-tcp -udp -syn -xmas -null -fyn",chr),chr,strlen(chr));
    return 0;
}
