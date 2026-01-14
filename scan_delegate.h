#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};
struct scan_info{
   char* target_ip;
   char* scan_type;
   int index;
   int port;
   int timeout_ms;
   struct addrinfo addr_info;
};
int resolve_hostname(const char* hostname,char *ip_buffer);
void get_machine_ip(char* buffer);
unsigned short calculate_checksum(unsigned short *ptr,int nbytes);
void set_tcp_flags(struct tcphdr *tcp,const char *scan_type);
int raw_scan(int sock,struct scan_info *info);
