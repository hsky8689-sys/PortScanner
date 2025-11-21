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
#include <poll.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/param.h>
#define MAX_FD_PER_PROCESS 1024
#define MAX_PORTS_PER_SOCKET 200
#define MAX_HOSTNAME_LENGTH 50
#define MAX_EPOLL_EVENTS 100
