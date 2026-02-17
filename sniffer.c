#define _DEFAULT_SOURCE
#define __FAVOR_BSD
#include "sniffer.h"

static pcap_t *main_sniffer = NULL;
static volatile sig_atomic_t stop_sniffing = 0;

void sigterm_handler(int sig){
   stop_sniffing = 1;
   if(main_sniffer)
	   pcap_breakloop(main_sniffer);
}

void setup_cleanup_signal(){
   struct sigaction sa;
   sa.sa_handler = sigterm_handler;
   sa.sa_flags = 0;
   sigemptyset(&sa.sa_mask);
   sigaction(SIGTERM,&sa,NULL);
   sigaction(SIGINT,&sa,NULL);
}

const char* default_services[65536] = {
    [0] = "reserved",
    [20] = "ftp-data",
    [21] = "ftp",
    [22] = "ssh",
    [23] = "telnet",
    [25] = "smtp",
    [53] = "domain",
    [80] = "http",
    [110] = "pop3",
    [111] = "rpcbind",
    [123] = "ntp",
    [143] = "imap2",
    [443] = "https",
    [993] = "imaps",
    [995] = "pop3s",

    [9929] = "unknown_service/emc_networker",

    // Backdoor common
    [31337] = "elite_backdoor",

    // Other common services
    [3306] = "mysql",
    [3389] = "ms-wbt-server",
    [5432] = "postgresql",
    [5900] = "vnc",
    [8080] = "http-alt",
};

char* get_default_service(int port) {
    if (port >= 0 && port < 65536 && default_services[port]) {
        return strdup(default_services[port]);
    }
    return "unknown";
}

char* grab_raw_banner(const char* ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return get_default_service(port);
    
    int flag = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    struct timeval tv = {8, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int attempts = 0;
    while (attempts < 2) {
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            break;
        }
        attempts++;
        sleep(1);
    }
    
    if (attempts == 2) {
        close(sock);
        return get_default_service(port);
    }
    
    char buffer[4096] = {0};
    fd_set readfds;
    int total_bytes = 0;
    
    for (int i = 0; i < 10; i++) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        struct timeval timeout = {1, 0};
        
        int ready = select(sock + 1, &readfds, NULL, NULL, &timeout);
        
        if (ready > 0 && FD_ISSET(sock, &readfds)) {
            int bytes = recv(sock, buffer + total_bytes, sizeof(buffer) - total_bytes - 1, 0);
            if (bytes > 0) {
                total_bytes += bytes;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    
    close(sock);
    
    if (total_bytes == 0) {
        return get_default_service(port);
    }
    
    buffer[total_bytes] = '\0';
    
    for (int i = 0; i < total_bytes; i++) {
        unsigned char c = buffer[i];
        if (c < 32 || c > 126) {
            buffer[i] = '.';
        }
    }
    
    
    while (total_bytes > 0 && buffer[total_bytes-1] == '.') {
        buffer[--total_bytes] = '\0';
    }
    
    char* end = strstr(buffer, "\r\n\r\n");
    if (end) *end = '\0';
    
    return strdup(buffer);
}

void syn_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if(header->len < 54)return;
    
    const struct ip *ip_header = (struct ip *)(packet + 14);
    int ip_header_len = ip_header->ip_hl * 4;

    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);

    uint8_t flags = tcp_header->th_flags;

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);
    
    if(scan_results->port_states[src_port]!=0) return;

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&ip_header->ip_src,src_ip,INET_ADDRSTRLEN);
    
    if((flags & (TH_SYN | TH_ACK)) == (TH_SYN|TH_ACK)){
	char* banner = grab_raw_banner(src_ip,src_port);
    strncpy(scan_results->banners[src_port],banner,strlen(banner));
	scan_results->port_states[src_port] = 1;
	return;
    }
    if(flags & TH_RST)
	scan_results->port_states[src_port] = 2;
}
void udp_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	    if(header->len < 36) return;

    const struct ip *ip_header = (const struct ip*)(packet + 14);
    int ip_hlen = ip_header->ip_hl * 4;

    struct in_addr target_ip;
    inet_aton("45.33.32.156", &target_ip);  // scanme.nmap.org
    if(ip_header->ip_src.s_addr != target_ip.s_addr) return;
    if(ip_header->ip_p != IPPROTO_ICMP) return;

    const struct icmphdr *icmp = (const struct icmphdr*)(packet + 14 + ip_hlen);

    if(icmp->type == ICMP_DEST_UNREACH) {
        const struct udphdr *udph = (const struct udphdr*)(packet + 14 + ip_hlen + 8);
        uint16_t dst_port = ntohs(udph->dest);

        if(dst_port < 1 || dst_port > 65535) return;

        if(scan_results->port_states[dst_port] != 0) return;

        switch(icmp->code) {
            case ICMP_PORT_UNREACH:  // Port CLOSED
                scan_results->port_states[dst_port] = 2;  // CLOSED
                break;

            case ICMP_HOST_UNREACH:    // Host down/filtered
            case ICMP_PROT_UNREACH:    // Protocol blocked
            case 9:  // Admin Filtered
            case 10: // Admin Prohibited
            case 13:
                scan_results->port_states[dst_port] = 3;  // FILTERED
                break;

            default:
                break;
        }
    }
}
void setup_udp_sniffer(char* hostname,char* interface){ 
    setup_cleanup_signal();

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp),
             "icmp and src host %s and icmp[0] = 3", hostname);  // Type=3 DEST_UNREACH

    char *dev = interface;
    bpf_u_int32 net, mask;

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0; mask = 0;
    }

    main_sniffer = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(!main_sniffer) {
        fprintf(stderr, " pcap_open_live %s: %s\n", dev, errbuf);
        return;
    }

    if(pcap_compile(main_sniffer, &fp, filter_exp, 0, net) == -1 ||
       pcap_setfilter(main_sniffer, &fp) == -1) {
        fprintf(stderr, " BPF '%s': %s\n", filter_exp, pcap_geterr(main_sniffer));
    }

    pcap_loop(main_sniffer, 0, udp_packet_handler, NULL);

    pcap_close(main_sniffer);
}
void setup_tcp_sniffer(char* hostname,char* interface) {
    setup_cleanup_signal();
    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    char filter_exp[] = "tcp";

    bpf_u_int32 mask;
    bpf_u_int32 net;
    char *dev = interface;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Cannot get mask for %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    main_sniffer = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (main_sniffer == NULL) {
        fprintf(stderr, "Cannot open device %s: %s\n", dev, errbuf);
        return;
    }


    if (pcap_compile(main_sniffer, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "BPF filter error: %s\n", pcap_geterr(main_sniffer));
        return;
    }

    if (pcap_setfilter(main_sniffer, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(main_sniffer));
        return;
    }

    pcap_setnonblock(main_sniffer, 1, errbuf);
    pcap_setdirection(main_sniffer, PCAP_D_IN);
 
    pcap_loop(main_sniffer, 0, syn_packet_handler, NULL);

    pcap_close(main_sniffer);
}
