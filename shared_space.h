#include<stdio.h>
#include<sys/mman.h>
#include "parser.h"
#define PORT_FILTERED 0
#define PORT_OPENED 1
#define PORT_CLOSED 2
#define MAX_PORTS 65537
#define SERVICE_SIZE 30
#define VERSION_SIZE 25
#define BANNER_SIZE 40
typedef struct{
   int  port_states[MAX_PORTS];
   char banners[MAX_PORTS][BANNER_SIZE];
   char services[MAX_PORTS][SERVICE_SIZE];
   char versions[MAX_PORTS][VERSION_SIZE];
}scan_results_t;
extern scan_results_t *scan_results;
int init_shared_memory();
void write_scan_result(struct parsed_input* parsed);
void deallocate_shared_memory();
