#include<sys/epoll.h>
#include<sys/socket.h>
#include<unistd.h>
#include<signal.h>
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<netinet/in.h>
#include<string.h>
#include<errno.h>
#include<arpa/inet.h>
#define MAX_FD_PER_PROCESS 1020
#define MAX_PORTS_PER_SOCKET 30
#define MAX_HOSTNAME_LENGTH 50
#define SOCKETS_NUMBER MAX_FD_PER_PROCESS/MAX_PORTS_PER_SOCKET
extern int* first;
extern int* last;
extern char* hostname;
extern int* sockets;
extern int* epoll;
extern struct sockaddr_in* connections_data;
extern struct epoll_event* events;

void process_end(sig_atomic_t signum);
int allocate_data();
int prepare_sockets(int first,int last);
int config_socket(int sock_index,int port);
int close_sockets(int first,int last);
void scan_specific_host(char* hostname,int first,int last);
int deallocate_data();
