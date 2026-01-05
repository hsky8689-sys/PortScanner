#include "scan_delegate.h"
void get_machine_ip(char* buffer){
   int sock = socket(AF_INET,SOCK_DGRAM,0);
   if(sock < 0){
      perror("socket");
      return;
   }
   struct sockaddr_in serv;
   serv.sin_family = AF_INET;
   serv.sin_addr.s_addr = inet_addr("8.8.8.8");
   serv.sin_port = htons(53);

   if(connect(sock,(const struct sockaddr*)&serv,sizeof(serv))<0){
      perror("connect");
      close(sock);
      return;
   }

   struct sockaddr_in name;
   socklen_t namelen = sizeof(name);
   if(getsockname(sock,(struct sockaddr*)&name,&namelen)<0)
	   perror("getsockname error");
   else strcpy(buffer,inet_ntoa(name.sin_addr));
   close(sock);
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
    else if(strcmp(scan_type,"fin") == 0)
	    tcp->fin=1;
    else if(strcmp(scan_type,"xmas") == 0)
	    tcp->fin=1,tcp->psh=1,tcp->urg=1;
    else if(strcmp(scan_type,"null") == 0);//all the flags are properly set
    //Specifying non existent scan types result in a null scan =))
}
int raw_scan(int sock,struct scan_info *info){

	if(sock<0){
	   perror("Somehow socket got closed before scan.Reopening...");
	   sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	}
	
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
        
	char src_ip[10000];
	get_machine_ip(src_ip);
	
	if(src_ip == NULL){
	   return -1;
	}

	iph->saddr = inet_addr(src_ip);
	iph->daddr = inet_addr(info->target_ip);

	tcph->source = htons(12345);///pana acum
	tcph->dest = htons(info->port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;

	set_tcp_flags(tcph,info->scan_type);

	tcph->window = htons(5840);
	tcph->check = 0;
	
	struct pseudo_header psh;
	psh.source_address = iph->saddr;
	psh.dest_address = iph->daddr;
	psh.placeholder = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	char* pseudogram = malloc(psize);
	if(pseudogram==NULL){
		perror("malloc");
	        return -EXIT_FAILURE;
	}
	memcpy(pseudogram,(char*)&psh,sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header),tcph,sizeof(struct tcphdr));
	tcph->check = calculate_checksum((unsigned short*)pseudogram,psize);
	//!!!
	int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = iph->daddr;

        int result = sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest));
    
        free(pseudogram);
        return result;
}
int main(){
   char buffer[10000];
   get_machine_ip(buffer);
   printf("%s",buffer);
   return 0;
}
