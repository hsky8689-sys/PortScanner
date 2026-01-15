#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/param.h>
#include "scan_delegate.h"
#include <pthread.h>
#define DEFAULT_TIMEOUT 1000
#define DEFAULT_MAX_CONCURRENT 500
#define MAX_FD_PER_PROCESS 1024
#define MAX_PORTS_PER_SOCKET 200
#define MAX_HOSTNAME_LENGTH 50
#define MAX_EPOLL_EVENTS 100
int* results;
int* scanned;
pthread_t threads[MAX_FD_PER_PROCESS];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t listener_thread;
int current_port,first,last,maxc,timeout_ms;
