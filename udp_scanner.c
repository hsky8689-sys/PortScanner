#define _GNU_SOURCE
#include "udp_scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>

//#define MAX_SCANS_PER_PORT 1

int raw_icmp_sock;
int *results;   // 0 = unknown, 1 = open, 2 = closed, 3 = open|filtered
int *scanned;
pthread_t *threads;
pthread_t listener_thread;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int current_port, first, last;
char target_ip[64];
int listen_running = 1;

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

struct scan_data {
    int port;
    int timeout_ms;
    int index;
};

/* trimite un singur UDP packet către target:port */
static void udp_probe(int port) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(target_ip);

    char msg[] = "udp_probe";
    sendto(udp_sock, msg, sizeof(msg), 0,
           (struct sockaddr *)&dest, sizeof(dest));

    close(udp_sock);
}

/* listener ICMP: marchează porturile closed pe baza ICMP type 3 code 3 */
void *icmp_listener(void *arg) {
    char buffer[65535];
    struct sockaddr_in saddr;
    socklen_t saddr_len = sizeof(saddr);

    while (listen_running) {
        int size = recvfrom(raw_icmp_sock, buffer, sizeof(buffer), 0,
                            (struct sockaddr *)&saddr, &saddr_len);
        if (size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            break;
        }

        struct iphdr *iph = (struct iphdr *)buffer;
        if (iph->protocol != IPPROTO_ICMP) continue;

        unsigned short iphdrlen = iph->ihl * 4;
        if (size < iphdrlen + (int)sizeof(struct icmphdr)) continue;

        struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen);

        if (icmph->type == 3 && icmph->code == 3) {
            /* ICMP dest unreachable / port unreachable */
            unsigned char *inner = (unsigned char *)(buffer + iphdrlen + sizeof(struct icmphdr));
            struct iphdr *orig_iph = (struct iphdr *)inner;
            if (orig_iph->protocol != IPPROTO_UDP) continue;

            unsigned short orig_iphdrlen = orig_iph->ihl * 4;
            if (size < iphdrlen + (int)sizeof(struct icmphdr) +
                        orig_iphdrlen + (int)sizeof(struct udphdr))
                continue;

            struct udphdr *orig_udph = (struct udphdr *)(inner + orig_iphdrlen);
            int port = ntohs(orig_udph->dest);

            if (port >= first && port <= last) {
                pthread_mutex_lock(&mutex);
                if (results[port] == 0) {
                    results[port] = 2; // closed
                }
                pthread_mutex_unlock(&mutex);
            }
        }
    }

    return NULL;
}

/* worker: ia porturi și trimite UDP probe */
void *worker(void *arg) {
    struct scan_data *data = (struct scan_data *)arg;

    while (1) {
        int my_port;

        pthread_mutex_lock(&mutex);
        if (current_port > last) {
            pthread_mutex_unlock(&mutex);
            break;
        }
        my_port = current_port++;
        pthread_mutex_unlock(&mutex);

        if (scanned[my_port] >= MAX_SCANS_PER_PORT) continue;

        scanned[my_port]++;
        udp_probe(my_port);
    }

    free(data);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <host_ip> <first_port> <last_port> [max_concurrent] [timeout_ms]\n", argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "UDP SCAN REQUIRES ROOT PRIVILEGES\n");
        exit(EXIT_FAILURE);
    }

    strncpy(target_ip, argv[1], sizeof(target_ip) - 1);
    target_ip[sizeof(target_ip) - 1] = '\0';

    first = atoi(argv[2]);
    last  = atoi(argv[3]);
    int maxc  = (argc >= 5) ? atoi(argv[4]) : 128;
    int timeout_ms = (argc >= 6) ? atoi(argv[5]) : 500;

    if (first < 1 || last < first || maxc <= 0 || last > 65535) {
        fprintf(stderr, "Bad args\n");
        return 1;
    }

    /* raw socket pentru ICMP */
    raw_icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_icmp_sock < 0) {
        perror("socket(ICMP)");
        exit(EXIT_FAILURE);
    }

    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(raw_icmp_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = timeout_ms * 1000;
    setsockopt(raw_icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    results = calloc(65536, sizeof(int));
    scanned = calloc(65536, sizeof(int));
    if (!results || !scanned) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    current_port = first;

    /* pornește listener ICMP */
    pthread_create(&listener_thread, NULL, icmp_listener, NULL);

    threads = calloc(maxc, sizeof(pthread_t));
    if (!threads) {
        perror("calloc threads");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < maxc; i++) {
        struct scan_data *info = malloc(sizeof(struct scan_data));
        if (!info) {
            perror("malloc scan_info");
            continue;
        }
        info->timeout_ms = timeout_ms;
        info->index = i;
        pthread_create(&threads[i], NULL, worker, info);
    }

    for (int i = 0; i < maxc; i++) {
        pthread_join(threads[i], NULL);
    }

    /* așteaptă ICMP-uri întârziate */
    usleep(timeout_ms * 1000);

    listen_running = 0;
    close(raw_icmp_sock);
    pthread_cancel(listener_thread);
    pthread_join(listener_thread, NULL);

    int filtered = 0;
    for (int p = first; p <= last; p++) {
        if (results[p] == 0 && scanned[p] > 0) {
            results[p] = 3; // open|filtered
        }
    }

    for (int p = first; p <= last; p++) {
        if (results[p] == 1)
            printf("%d open\n", p);
    }
    for (int p = first; p <= last; p++) {
        if (results[p] == 3) {
            printf("%d open|filtered\n", p);
            filtered++;
        }
    }
    for (int p = first; p <= last; p++) {
        if (results[p] == 2)
            printf("%d closed\n", p);
    }

    printf("Found %d open|filtered ports\n", filtered);

    free(results);
    free(scanned);
    free(threads);
    return 0;
}

