#include "scan_delegate.h"
char* get_machine_ip(){
   char hostname[256];
   struct hostent *host_info;
   struct in_addr *addr;

   gethostname(hostname,sizeof(hostname));
   host_info = gethostbyname(hostname);
   
   if(host_info != NULL){
      addr = (struct in_addr*)host_info->h_addr_list[0];
      printf("Hostname: %s\n", hostname);
      char* res = inet_ntoa(*addr);
      printf("Local IP Address: %s\n", res);
      return res;
   }
   perror("Could not receive local IP adress");
   return NULL;
}
unsigned short calculate_checksum(unsigned short *ptr,int nbytes){
   long sum;
   unsigned short oddbyte;
   short answer;

   sum = 0;
   while(nbytes > 1){
      sum += *ptr++;
      nbytes -= 2;
   }
   if(nbytes == 1){
      oddbyte = 0;
      *((unsigned char *)&oddbyte) = *(unsigned char*) ptr;
      sum += oddbyte;
   }

   sum = (sum >> 16) + (sum & 0xffff);
   sum = sum + (sum >> 16);
   answer = (short) ~sum;

   return answer;
}
void set_tcp_flags(struct tcphdr *tcp,const char* scan_type){
    tcp->syn = 0;
    tcp->fin = 0;
    tcp->psh = 0;
    tcp->urg = 0;
    tcp->ack = 0;
    tcp->rst = 0;
    if(strcmp(scan_type,"syn") == 0)
	    tcp->syn = 1;
    else if(strcmp(scan_type,"syn") == 0)
	    tcp->fin=1;
    else if(strcmp(scan_type,"xmas") == 0)
	    tcp->fin=1,tcp->psh=1,tcp->urg=1;
    else if(strcmp(scan_type,"null") == 0);//all the flags are properly set
}
int raw_scan(char* target_ip,int port,char* scan_type){
	char datagram[4096];
	memset(datagram,0,4096);

	struct iphdr *iph = (struct iphdr*) datagram;
	struct tcphdr *tcph = (struct tcphdr*) (datagram+sizeof(struct ip));
	
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph->id = htons(54321);
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
        
	char* src_ip = get_machine_ip();
	if(src_ip == NULL){
	   return -1;
	}

	iph->saddr = inet_addr(src_ip);
	iph->daddr = inet_addr(target_ip);

	tcph->source = htons(12345);///pana acum
	tcph->dest = htons(port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;

	set_tcp_flags(tcph,scan_type);

	tcph->window = htons(5840);
	tcph->check = 0;
	
}
int main(){
   get_machine_ip();
   return 0;
}
