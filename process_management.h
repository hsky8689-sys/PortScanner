#include "sniffer.h"
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
parsed_input* parsed;
char command[MAX_CHARACTERS];
//de schimbat display_text
char display_text[] = "1.Show active connections\n2.Scan specific connection\n-----------------\nCommand";
extern pthread_mutex_t mutex;
extern void worker(int task_id);
extern int next_task();
extern void menu();
