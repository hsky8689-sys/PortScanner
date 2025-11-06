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
#include <sys/param.h>
#include<arpa/inet.h>
#define MAX_FD_PER_PROCESS 100
#define MAX_PORTS_PER_SOCKET 200
#define MAX_HOSTNAME_LENGTH 50
#define MAX_EPOLL_EVENTS 100
#define SOCKETS_NUMBER MAX_FD_PER_PROCESS/MAX_PORTS_PER_SOCKET
extern int* first;
extern int* last;
extern char* hostname;
extern int* sockets;
extern int* epoll;
extern struct sockaddr_in* connections_data;
extern struct epoll_event* events;
extern struct epoll_event* recieve_data;
extern int* sockets_needed;
typedef struct{
   int first,last;
}range;
extern range* ranges;
void process_end(sig_atomic_t signum);
int allocate_data();
int compute_sockets_number(int first,int last);
int config_epoll();
int close_epoll();
int prepare_sockets();
int config_socket(int sock_index,int port);
int close_sockets(int first,int last);
int scan_specific_host(char* hostname);
int reallocate_data(int newsize);
int deallocate_data();
