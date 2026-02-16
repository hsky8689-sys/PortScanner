#include "udp_scanner.h"

int raw_icmp_sock;
pthread_t *threads;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int current_port, first, last;
char source_ip[64];
char target_ip[64];

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* worker: ia porturi și trimite UDP probe */
void *worker(void *arg) {
    struct scan_info *data = (struct scan_info*)arg;

    while (1) {
        int my_port = data->index;

        pthread_mutex_lock(&mutex);
	if (current_port > last) {
            pthread_mutex_unlock(&mutex);
            break;
        }
        my_port = current_port++;
        pthread_mutex_unlock(&mutex);
	data->port = my_port;
	udp_scan(raw_icmp_sock,source_ip,data);
	usleep(50000);
    }
    free(data->target_ip);
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

    if(inet_addr(argv[1]) == INADDR_NONE){
	if(resolve_hostname(argv[1],target_ip)!=0){
	    fprintf(stderr,"Could not resolve hostname");
	    return -1;
	}
	printf("Found IP: %s\n",target_ip);
    }
    else strcpy(target_ip,argv[1]);

    first = atoi(argv[2]);
    last  = atoi(argv[3]);
    int maxc  = (argc >= 5) ? atoi(argv[4]) : 100;
    int timeout_ms = (argc >= 6) ? atoi(argv[5]) : 1000;

    if (first < 1 || last < first || maxc <= 0 || last > 65535) {
        fprintf(stderr, "Bad args\n");
        return 1;
    }

    get_machine_ip(source_ip);
    if(!source_ip[0]){
	perror("Could not retrieve machine ip\n");
	return -EXIT_FAILURE;
    }

    /* raw socket pentru ICMP */
    raw_icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_icmp_sock < 0) {
        perror("socket(ICMP)");
        exit(EXIT_FAILURE);
    }

    int sndbuf = 4 * 1024 * 1024;
    if(setsockopt(raw_icmp_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf))<0){
     	perror("setsockopt1");
	return EXIT_FAILURE;
    }

    current_port = first;

    threads = calloc(maxc, sizeof(pthread_t));
    if (!threads) {
        perror("calloc threads");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < maxc; i++) {
        struct scan_info *info = malloc(sizeof(struct scan_info));
        memset(info,0,sizeof(struct scan_info));
	if (!info) {
            perror("malloc scan_info");
            continue;
        }
        info->timeout_ms = timeout_ms;
        info->target_ip = calloc(64,sizeof(char));
	if(info->target_ip == NULL){
	 	perror("malloc");
		break;
	}

	strncpy(info->target_ip,target_ip,sizeof(target_ip)-1);
        pthread_create(&threads[i], NULL, worker, info);
    }

    for (int i = 0; i < maxc; i++) {
        pthread_join(threads[i], NULL);
    }

    /* așteaptă ICMP-uri întârziate */
    usleep(timeout_ms * 1000);

    close(raw_icmp_sock);

    free(threads);
    return 0;
}

