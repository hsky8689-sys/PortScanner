//#define __FAVOR_BSD
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>                                                 
#include <netinet/ip.h>
#include "shared_space.h"
#include <netinet/udp.h>
extern scan_results_t* scan_results;
void syn_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void udp_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void setup_tcp_sniffer(char* hostname,char* interface);
void setup_udp_sniffer(char* hostname,char* interface);
