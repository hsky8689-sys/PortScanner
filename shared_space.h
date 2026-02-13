#include<stdio.h>
#include<sys/mman.h>
#include "parser.h"
#define PORT_FILTERED 0
#define PORT_OPENED 1
#define PORT_CLOSED 2
#define MAX_PORTS 65535
#define SERVICE_SIZE 30
#define VERSION_SIZE 25
typedef struct{
   int  port_states[MAX_PORTS];
   char services[MAX_PORTS][SERVICE_SIZE];
   char versions[MAX_PORTS][VERSION_SIZE];
}scan_results_t;
scan_results_t *results = NULL;
