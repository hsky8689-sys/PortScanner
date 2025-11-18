#include"scanner.h"
#include"sniffer.h"
#define task_show_connections 1
#define task_scan 2
#define task_sniff 3
#define task_analyze 4
char display_text[] = "1.Show active connections\n2.Scan specific connection\n-----------------\nCommand";
extern void worker(int task_id);
extern void menu();
