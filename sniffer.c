#define _DEFAULT_SOURCE
#define __FAVOR_BSD
#include "sniffer.h"

// Funcția care procesează pachetele
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if(header->len < 54)return;

    //printf("HEX DUMP (bytes 34-54):\n");
    for(int i=34; i<54 && i<header->len; i++) {
    //    printf("%02x ", packet[i]);
    }
    //printf("\n");

    const struct ip *ip_header = (struct ip *)(packet + 14); // Sărim peste header-ul Ethernet
    int ip_header_len = ip_header->ip_hl * 4;

    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);

    uint8_t flags = tcp_header->th_flags;

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&ip_header->ip_src,src_ip,INET_ADDRSTRLEN);

    /*printf("[DEBUG] %s:%d->%d Flags:0x%02X (",src_ip,src_port,dst_port,flags);
    if(flags & TH_FIN) printf("FIN ");
    if(flags & TH_SYN) printf("SYN ");
    if(flags & TH_RST) printf("RST ");
    if(flags & TH_ACK) printf("ACK ");
    printf(")\n");
    */
    if((flags & (TH_SYN | TH_ACK)) == (TH_SYN|TH_ACK)){
        /*
	printf("[+]PORT DESCHIS (SYN-ACK): %d -> %s:%d\n",dst_port,src_ip,src_port);
	*/
	results->port_states[dst_port] = 1;
	return;
    }
    if(flags & TH_RST){
       /*printf("[-]PORT INCHIS (RST): %d -> %s:%d\n",dst_port,src_ip,src_port);
       fflush(stdout);
       */
	results->port_states[dst_port] = 2;
    }
   
    /*
    if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {

	  fprintf(stdout,"[+] Port DESCHIS (SYN-ACK): %d \tla IP: %s\n",
               ntohs(tcp_header->th_sport),
               inet_ntoa(ip_header->ip_src));
            
	  
    }
    // CAZ 2: RST (Port Închis)
    // Verificăm dacă flag-ul RST este setat
    else if (tcp_header->th_flags & TH_RST) {
	  
//	  fprintf(stdout,"[-] Port INCHIS  (RST)    : %d \tla IP: %s\n",
 //             ntohs(tcp_header->th_sport),
   //           inet_ntoa(ip_header->ip_src));
	       //fclose(log);
	
    }
    */
}

void setup_sniffer(char* hostname,char* interface) {

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

    printf("Sniffer pornit pe %s.\nFiltrez pachete SYN-ACK (Open) și RST (Closed)...\n", dev);
    
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
}
/*
int main(int argc,char** argv){
   setup_sniffer("scanme.nmap.org","eth0");
   return 0;
}
*/
