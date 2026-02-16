#define _DEFAULT_SOURCE
#define __FAVOR_BSD
#include "sniffer.h"

// Funcția care procesează pachetele
void syn_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if(header->len < 54)return;
    
    const struct ip *ip_header = (struct ip *)(packet + 14); // Sărim peste header-ul Ethernet
    int ip_header_len = ip_header->ip_hl * 4;

    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);

    uint8_t flags = tcp_header->th_flags;

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);
    
    if(scan_results->port_states[dst_port]!=0)
	    return;

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&ip_header->ip_src,src_ip,INET_ADDRSTRLEN);
  
    if((flags & (TH_SYN | TH_ACK)) == (TH_SYN|TH_ACK)){
        
	//printf("[+]PORT DESCHIS (SYN-ACK): %d -> %s:%d\n",dst_port,src_ip,src_port);
	
	scan_results->port_states[src_port] = 1;
	return;
    }
    if(flags & TH_RST){
       //printf("[-]PORT INCHIS (RST): %d -> %s:%d\n",dst_port,src_ip,src_port);
       //fflush(stdout);
       
	scan_results->port_states[src_port] = 2;
    }
}
void udp_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	    if(header->len < 36) return;  // cica 42 Min IP+ICMP+UDP size

    const struct ip *ip_header = (const struct ip*)(packet + 14);
    int ip_hlen = ip_header->ip_hl * 4;

    struct in_addr target_ip;
    inet_aton("45.33.32.156", &target_ip);  // scanme.nmap.org
    if(ip_header->ip_src.s_addr != target_ip.s_addr) return;
    if(ip_header->ip_p != IPPROTO_ICMP) return;

    const struct icmphdr *icmp = (const struct icmphdr*)(packet + 14 + ip_hlen);

    // 🔥 ICMP Destination Unreachable (UDP probe replies)
    if(icmp->type == ICMP_DEST_UNREACH) {
        printf("🎯 ICMP DEST_UNREACH Type=%d Code=%d\n", icmp->type, icmp->code);

        // 🔥 Extrage UDP header din ICMP payload
        const struct udphdr *udph = (const struct udphdr*)(packet + 14 + ip_hlen + 8);
        uint16_t dst_port = ntohs(udph->dest);  // Portul TĂU scanat!

        if(dst_port < 1 || dst_port > 65535) return;

        // Verifică dacă deja scanat
        if(scan_results->port_states[dst_port] != 0) return;

        switch(icmp->code) {
            case ICMP_PORT_UNREACH:  // Port CLOSED
                printf(" UDP Port %d CLOSED (Port Unreachable)\n", dst_port);
                scan_results->port_states[dst_port] = 2;  // CLOSED
                break;

            case ICMP_HOST_UNREACH:    // Host down/filtered
            case ICMP_PROT_UNREACH:    // Protocol blocked
            case 9:  // Admin Filtered
            case 10: // Admin Prohibited
            case 13:
                printf("🔒 UDP Port %d FILTERED (Code %d)\n", dst_port, icmp->code);
                scan_results->port_states[dst_port] = 3;  // FILTERED
                break;

            default:
                printf("⚠️  UDP Port %d UNKNOWN ICMP Code %d\n", dst_port, icmp->code);
                break;
        }
    }
}
void setup_udp_sniffer(char* hostname,char* interface){
	printf(" UDP Sniffer PID: %d (target: %s)\n", getpid(), hostname);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;

    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp),
             "icmp and src host %s and icmp[0] = 3", hostname);  // Type=3 DEST_UNREACH

    char *dev = interface;
    bpf_u_int32 net, mask;

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0; mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(!handle) {
        fprintf(stderr, " pcap_open_live %s: %s\n", dev, errbuf);
        return;
    }

    // Compile + set BPF filter
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ||
       pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, " BPF '%s': %s\n", filter_exp, pcap_geterr(handle));
    }

    printf(" UDP Sniffer live: '%s'\n", filter_exp);
    pcap_loop(handle, 0, udp_packet_handler, NULL);

    pcap_close(handle);
}
void setup_tcp_sniffer(char* hostname,char* interface) {

    printf("sniffer PID: %d, EUID: %d\n",
           getpid(), geteuid());
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    
    // MODIFICARE FILTRU:
    // "tcp" - orice pachet TCP
    // "((tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))" - care este SYN-ACK
    // " or " - SAU
    // "(tcp[tcpflags] & tcp-rst != 0))" - care are flag-ul RST setat
    //char filter_exp[] = "tcp and ((tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)) or (tcp[tcpflags] & tcp-rst != 0))";
    char filter_exp[] = "tcp";

    bpf_u_int32 mask;
    bpf_u_int32 net;
    char *dev = interface; // Asigură-te că aceasta este interfața corectă

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Nu pot obține masca pentru %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Nu pot deschide device-ul %s: %s\n", dev, errbuf);
        return;
    }

    // Compilăm noul filtru
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Eroare filtru BPF: %s\n", pcap_geterr(handle));
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Eroare setare filtru: %s\n", pcap_geterr(handle));
        return;
    }

    pcap_setnonblock(handle, 1, errbuf);  // Non-blocking
    pcap_setdirection(handle, PCAP_D_IN);

    printf("Sniffer pornit pe %s.\nFiltrez pachete SYN-ACK (Open) și RST (Closed)...\n", dev);
    
    pcap_loop(handle, 0, syn_packet_handler, NULL);

    pcap_close(handle);
}
/*
int main(int argc,char** argv){
   setup_udp_sniffer("scanme.nmap.org","eth0");
   return 0;
}*/
