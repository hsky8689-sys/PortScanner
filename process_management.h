#include"tcp_scanner.h"
#include"udp_scanner.h"
#include"sniffer.h"
#include"parser.h"
#include<pthread.h>
parsed_input* parsed;
char command[MAX_CHARACTERS];
char display_text[] = "1.Show active connections\n2.Scan specific connection\n-----------------\nCommand";
extern pthread_mutex_t mutex;
int processes_needed;
extern void worker(int task_id);
extern int next_task();
extern void menu();
