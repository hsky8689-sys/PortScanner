#include<pcap/pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<netinet/tcp.h>                                                 
#include<netinet/ip.h>
#include"shared_space.h"
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void setup_sniffer(char* hostname,char* interface);
