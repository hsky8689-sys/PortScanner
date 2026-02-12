#define _DEFAULT_SOURCE
#define __FAVOR_BSD
#include "sniffer.h"
FILE* open_file(char* filename){
   FILE* log = fopen(filename,"a");
   return log;
}
// Funcția care procesează pachetele
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    fprintf(stdout,"Pachet interceptat! Lungime: %d\n", header->len);
    const struct ip *ip_header = (struct ip *)(packet + 14); // Sărim peste header-ul Ethernet
    int ip_header_len = ip_header->ip_hl * 4;

    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);

    // Verificăm flag-urile pentru a determina starea portului
    
    // CAZ 1: SYN-ACK (Port Deschis)
    // Verificăm dacă sunt setate ambele flag-uri: SYN și ACK
    if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {

	  fprintf(stdout,"[+] Port DESCHIS (SYN-ACK): %d \tla IP: %s\n",
               ntohs(tcp_header->th_sport),
               inet_ntoa(ip_header->ip_src));
            
	  
    }
    // CAZ 2: RST (Port Închis)
    // Verificăm dacă flag-ul RST este setat
    else if (tcp_header->th_flags & TH_RST) {
	  
	  fprintf(stdout,"[-] Port INCHIS  (RST)    : %d \tla IP: %s\n",
               ntohs(tcp_header->th_sport),
               inet_ntoa(ip_header->ip_src));
	       //fclose(log);
	
    }
}
/*
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int offset;
    const struct ip *ip_header;

    // Încercăm să detectăm offset-ul corect
    // Verificăm dacă la +14 avem versiunea 4 (IPv4)
    if (((struct ip *)(packet + 14))->ip_v == 4) {
        offset = 14;
    } 
    // Dacă nu, verificăm la +16 (specific interfeței "any")
    else if (((struct ip *)(packet + 16))->ip_v == 4) {
        offset = 16;
    } 
    else {
        // Dacă niciuna nu e 4, pachetul nu e IPv4 sau e alt tip de link
        return; 
    }

    ip_header = (struct ip *)(packet + offset);
    int ip_header_len = ip_header->ip_hl * 4;

    // Verificăm dacă pachetul chiar este TCP
    if (ip_header->ip_p != IPPROTO_TCP) return;

    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + offset + ip_header_len);

    // DEBUG: Printează TOT ce găsește pe TCP, indiferent de flag-uri
    printf("[DEBUG] Pachet de la %s:%d | Flag-uri brute: 0x%02x\n", 
           inet_ntoa(ip_header->ip_src), 
           ntohs(tcp_header->th_sport), 
           tcp_header->th_flags);

    // Logică flag-uri
    if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        printf("[+] Port DESCHIS (SYN-ACK): %d\n", ntohs(tcp_header->th_sport));
    }
    else if (tcp_header->th_flags & TH_RST) {
        printf("[-] Port INCHIS (RST): %d\n", ntohs(tcp_header->th_sport));
    }
}
*/
void setup_sniffer(char* hostname,char* interface) {
    setvbuf(stdout, NULL, _IONBF, 0);

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
}*/

