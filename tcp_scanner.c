#include"tcp_scanner.h"
struct slot {
    int fd;             // socket fd, -1 if free
    int port;           // port being scanned
    long long start_ms; // when connect() started
};

static long long now_ms(void){
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec*1000 + t.tv_nsec/1000000;
}

static int set_nonblock(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* start a non-blocking connect into slot 's'; returns:
   1 = immediate success (rare)
   0 = immediate failure (connect refused)
  -1 = started and pending (EINPROGRESS)
  -2 = fatal (alloc/epoll-like failure) */
static int start_connect_slot(int ep_port, struct slot *s, struct sockaddr *addr_template, socklen_t alen, int port) {
    int fd = socket(addr_template->sa_family, SOCK_STREAM, 0);
    if (fd < 0) return -2;
    if (set_nonblock(fd) < 0) { close(fd); return -2; }

    // copy template and set port
    if (addr_template->sa_family == AF_INET) {
        struct sockaddr_in tmp;
        memcpy(&tmp, addr_template, sizeof(tmp));
        tmp.sin_port = htons((uint16_t)port);
        int rc = connect(fd, (struct sockaddr*)&tmp, sizeof(tmp));
        if (rc == 0) { close(fd); return 1; } // instant connect
        if (rc < 0 && errno != EINPROGRESS) { close(fd); return 0; } // immediate fail
    } else if (addr_template->sa_family == AF_INET6) {
        struct sockaddr_in6 tmp6;
        memcpy(&tmp6, addr_template, sizeof(tmp6));
        tmp6.sin6_port = htons((uint16_t)port);
        int rc = connect(fd, (struct sockaddr*)&tmp6, sizeof(tmp6));
        if (rc == 0) { close(fd); return 1; }
        if (rc < 0 && errno != EINPROGRESS) { close(fd); return 0; }
    } else {
        close(fd); return 0;
    }

    // pending
    s->fd = fd;
    s->port = port;
    s->start_ms = now_ms();
    return -1;
}

int main(int argc, char **argv){
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <host> <first_port> <last_port> [max_concurrent] [timeout_ms]\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];
    int first = atoi(argv[2]);
    int last  = atoi(argv[3]);
    int maxc  = (argc >= 5) ? atoi(argv[4]) : 128;
    int timeout_ms = (argc >= 6) ? atoi(argv[5]) : 500;
    if (first < 1 || last < first || maxc <= 0) { fprintf(stderr,"bad args\n"); return 1; }

    // resolve host (IPv4/IPv6 prefer IPv4 first)
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) { perror("getaddrinfo"); return 1; }

    // pick first usable (prefer AF_INET)
    struct sockaddr_storage addr_st;
    socklen_t alen = 0;
    struct addrinfo *rp;
    for (rp = res; rp; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
            memcpy(&addr_st, rp->ai_addr, rp->ai_addrlen);
            alen = rp->ai_addrlen;
            break;
        }
    }
    if (alen == 0) { fprintf(stderr,"no usable addr\n"); freeaddrinfo(res); return 1; }
    freeaddrinfo(res);

    int total = last - first + 1;
    unsigned char *result = calloc(total, 1); // 0 = closed/unknown, 1 = open
    if (!result) { perror("calloc"); return 1; }

    struct slot *slots = calloc(maxc, sizeof(struct slot));
    struct pollfd *pfds = calloc(maxc, sizeof(struct pollfd));
    if (!slots || !pfds) { perror("calloc"); return 1; }
    for (int i = 0; i < maxc; ++i) { slots[i].fd = -1; pfds[i].fd = -1; pfds[i].events = POLLOUT; }

    int active = 0;
    int next_port = first;

    // bootstrap
    while (next_port <= last && active < maxc) {
        int rc = start_connect_slot(next_port, &slots[active], (struct sockaddr*)&addr_st, alen, next_port);
        if (rc == 1) { result[next_port - first] = 1; printf("open: %d (instant)\n", next_port); }
        else if (rc == -1) {
            pfds[active].fd = slots[active].fd;
            pfds[active].events = POLLOUT;
            active++;
        } // rc == 0 -> immediate fail, just continue
        next_port++;
    }

    while (active > 0 || next_port <= last) {
        int poll_timeout = 100; // wake periodically to check timeouts
        int n = poll(pfds, active, poll_timeout);
        long long now = now_ms();

        if (n < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        // handle ready fds
        for (int i = 0; i < active; ++i) {
            if (pfds[i].fd < 0) continue;
            if (pfds[i].revents == 0) continue;

            int fd = pfds[i].fd;
            int port = slots[i].port;

            if (pfds[i].revents & (POLLERR | POLLHUP)) {
                // check error
                int so_err = 0; socklen_t sl = sizeof(so_err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &sl) < 0) so_err = errno;
                if (so_err == 0) {
                    result[port - first] = 1;
                  //  printf("open: %d\n", port);
                } else {
                    // closed/refused
                    // printf("closed: %d err=%s\n", port, strerror(so_err));
                }
            } else if (pfds[i].revents & POLLOUT) {
                int so_err = 0; socklen_t sl = sizeof(so_err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &sl) < 0) so_err = errno;
                if (so_err == 0) {
                    result[port - first] = 1;
                    //printf("open: %d\n", port);
                } else {
                    //printf("closed: %d err=%s\n", port, strerror(so_err));
                }
            }

            // cleanup slot i
            close(fd);
            slots[i].fd = -1;
            pfds[i].fd = -1;

            // mark consumed
            // note: if connection was instant earlier we already marked result
            // advance to next_port if available
            if (next_port <= last) {
                int p = next_port++;
                int rc = start_connect_slot(p, &slots[i], (struct sockaddr*)&addr_st, alen, p);
                if (rc == 1) {
                    result[p - first] = 1;
                    //printf("open: %d (instant)\n", p);
                    // slot remains free, try assign another immediately by decreasing i to revisit
                    // to avoid complexity, we'll assign pfds[i] = -1 and attempt refill below
                    pfds[i].fd = -1;
                    slots[i].fd = -1;
                } else if (rc == -1) {
                    pfds[i].fd = slots[i].fd;
                    pfds[i].events = POLLOUT;
                    pfds[i].revents = 0;
                } else {
                    // immediate fail -> leave slot to be filled by next loop
                    pfds[i].fd = -1;
                    slots[i].fd = -1;
                }
            } else {
                // no more ports; shrink active area by moving last active into i
                // find last active index (active-1) and move to i if i is not last
                if (i < active - 1) {
                    // move last into here
                    pfds[i] = pfds[active - 1];
                    slots[i] = slots[active - 1];
                    // restart processing this index in next iteration (decrement i so for(i++) cancels)
                    i--; // we'll process moved entry in later loop iterations
                }
                active--;
            }
        } // end for events

        // fill free slots if we had instant successes above
        for (int i = 0; i < maxc && next_port <= last; ++i) {
            if (active >= maxc) break;
            if (i < active) continue; // already part of active set
            if (pfds[i].fd != -1) continue;
            int p = next_port++;
            int rc = start_connect_slot(p, &slots[i], (struct sockaddr*)&addr_st, alen, p);
            if (rc == 1) {
                result[p - first] = 1;
                //printf("open: %d (instant)\n", p);
                continue;
            } else if (rc == -1) {
                pfds[i].fd = slots[i].fd;
                pfds[i].events = POLLOUT;
                pfds[i].revents = 0;
                active++;
            } else {
                // fail immediate, skip
            }
        }

        // timeout handling: if any slot exceeds timeout_ms, consider it closed and recycle
        for (int i = 0; i < active; ++i) {
            if (pfds[i].fd < 0) continue;
            if (slots[i].start_ms > 0 && now - slots[i].start_ms >= timeout_ms) {
                int port = slots[i].port;
                //printf("timeout: %d\n", port);
                close(pfds[i].fd);
                pfds[i].fd = -1; slots[i].fd = -1;
                // try to assign next port immediately
                if (next_port <= last) {
                    int p = next_port++;
                    int rc = start_connect_slot(p, &slots[i], (struct sockaddr*)&addr_st, alen, p);
                    if (rc == 1) { result[p - first] = 1; 
			    //printf("open: %d (instant)\n", p); 
			    }
                    else if (rc == -1) { pfds[i].fd = slots[i].fd; pfds[i].events = POLLOUT; pfds[i].revents = 0; }
                } else {
                    // shrink active set: move last
                    if (i < active - 1) {
                        pfds[i] = pfds[active - 1];
                        slots[i] = slots[active - 1];
                        i--; // re-evaluate moved
                    }
                    active--;
                }
            }
        }
    } // main loop

    // print results
    printf("Scan finished. Open ports:\n");
    for (int p = first; p <= last; ++p) if (result[p - first]) printf("%d\n", p);

    // cleanup
    for (int i = 0; i < maxc; ++i) if (pfds[i].fd >= 0) close(pfds[i].fd);
    free(result);
    free(slots);
    free(pfds);
    return 0;
}
