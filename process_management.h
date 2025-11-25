#include"tcp_scanner.h"
#include"udp_scanner.h"
#include"sniffer.h"
#include"parser.h"
#define max_processes 800
#define task_show_connections 1
#define task_scan 2
#define task_sniff 3
#define task_analyze 4
#define task_read 5
#define task_exit 6
parsed_input* parsed;
char command[MAX_CHARACTERS];
char display_text[] = "1.Show active connections\n2.Scan specific connection\n-----------------\nCommand";
extern void worker(int task_id);
extern int next_task();
extern void menu();
