#include<sys/epoll.h>
#include<sys/socket.h>
#include<unistd.h>
#include<signal.h>
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<netinet/in.h>
#include<string.h>
#include <arpa/inet.h>
#define MAX_FD_PER_PROCESS 1024
#define MAX_HOSTNAME_LENGTH 50
extern int* first;
extern int* last;
extern char* hostname;
extern int* sockets;
extern void** cleanup;
extern int* epoll;
int allocate_data();
int prepare_sockets(int first,int last);
int close_sockets(int first,int last);
void scan_specific_host(char* hostname,int first,int last);
int deallocate_data();
