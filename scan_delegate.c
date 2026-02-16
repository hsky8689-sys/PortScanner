#include "scan_delegate.h"
uint32_t cookie;
int get_max_threads_allowed(){
   struct rlimit limit;
   if(getrlimit(RLIMIT_NPROC,&limit) != 0){
      perror("getrlimit");
      return 100;
   }
   return (int)limit.rlim_cur;
}
int resolve_hostname(const char* hostname,char *ip_buffer){
   struct addrinfo hints,*res;
   struct sockaddr_in *addr;
   
   memset(&hints,0,sizeof(hints));
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_STREAM;

   if(getaddrinfo(hostname,NULL,&hints,&res)!=0)return -1;

   addr = (struct sockaddr_in *)res->ai_addr;
   strcpy(ip_buffer,inet_ntoa(addr->sin_addr));

   freeaddrinfo(res);
   return 0;
}
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
    if(strcmp(scan_type,"-syn") == 0)
	    tcp->syn = 1;
    else if(strcmp(scan_type,"-fin") == 0)
	    tcp->fin=1;
    else if(strcmp(scan_type,"-xmas") == 0)
	    tcp->fin=1,tcp->psh=1,tcp->urg=1;
    else if(strcmp(scan_type,"-null") == 0);//all the flags are properly set
}
int udp_scan(int sock,char* source_ip,struct scan_info* info){
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 8];
    struct iphdr *iph = (struct iphdr*)packet;
    struct udphdr *udph = (struct udphdr*)(packet + sizeof(struct iphdr));
    
    memset(udph,0,sizeof(struct udphdr));
    memset(packet, 0, sizeof(packet));

    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 8);
    iph->id = htons(rand() % 65353);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = inet_addr(source_ip); 
    iph->daddr = inet_addr(info->target_ip);
    iph->check = 0;  // Kernel calculează
    
    
    udph->source = htons(rand() % 65353);  // Random src port
    udph->dest = htons(info->port);
    udph->len = htons(sizeof(struct udphdr) + 8);
    udph->check = 0;
    
   
    char *payload = (char*)(udph + 1);
    strcpy(payload, "Hello?");
    
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(info->target_ip);
    
    int total_len = ntohs(iph->tot_len);
    int res = sendto(sock, packet, total_len, 0, 
                     (struct sockaddr*)&addr, sizeof(addr));
    
    if(res < 0) 
	    perror("sendto"); 
	    
    usleep(500);
    return res;
}
int raw_scan(int sock,char* source_ip,struct scan_info *info){
	
	if(!source_ip[0]){
	   perror("Source IP not found\n");
	   return -1;
	}

	char datagram[4096];
	memset(datagram,0,sizeof(datagram));

	struct iphdr *iph = (struct iphdr*) datagram;
	struct tcphdr *tcph = (struct tcphdr*) (datagram+sizeof(struct ip));
	memset(tcph,0,sizeof(struct tcphdr));

	iph->check = 0;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	iph->id = htons(rand() % 65353);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;

	iph->saddr = inet_addr(source_ip);
	iph->daddr = inet_addr(info->target_ip);

	int src_port = rand() % 65353;
	
	tcph->source = htons(src_port);

	tcph->dest = htons(info->port);
	
	uint32_t seed = cookie + iph->daddr + tcph->dest + tcph->source;
	
	tcph->seq = htonl(seed);

	tcph->ack_seq = 0;
	tcph->doff = 5;

	set_tcp_flags(tcph,info->scan_type);

	tcph->window = htons(5840);
	tcph->check = 0;
	
	struct pseudo_header psh;
	memset(&psh,0,sizeof(struct pseudo_header));

	psh.source_address = iph->saddr;
	psh.dest_address = iph->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	unsigned char* pseudogram = calloc(1,psize+2);
	if(pseudogram){
	     memset(pseudogram,0,psize+2);
	     memcpy(pseudogram,(char*)&psh,sizeof(struct pseudo_header));
	     memcpy(pseudogram + sizeof(struct pseudo_header),tcph,sizeof(struct tcphdr));
	     tcph->check = calculate_checksum((unsigned short*)pseudogram,psize);
	    free(pseudogram);
	}
	else perror("calloc");

        struct sockaddr_in dest;
        memset(&dest,0,sizeof(dest));
	dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = iph->daddr;

	int length = sizeof(struct iphdr) + sizeof(struct tcphdr);
        
	int result = sendto(sock, datagram, length, 0, (struct sockaddr *)&dest, sizeof(dest));

	usleep(500);
	if(result < 0){
        int err = errno;
              fprintf(stderr, "[ERROR] Port %d: Result=%d, Errno=%d (%s)\n", info->port, result, err, strerror(err));
	}
	
	return result;
}
