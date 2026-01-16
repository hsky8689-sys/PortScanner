#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
}__attribute__((packed));
struct scan_info{
   char* target_ip;
   char* scan_type;
   int index;
   int port;
   int timeout_ms;
   struct addrinfo addr_info;
}__attribute__((packed));
int get_max_threads_allowed();
int resolve_hostname(const char* hostname,char *ip_buffer);
void get_machine_ip(char* buffer);
unsigned short calculate_checksum(unsigned short *ptr,int nbytes);
void set_tcp_flags(struct tcphdr *tcp,const char *scan_type);
int raw_scan(int sock,char* source_ip,struct scan_info *info);
