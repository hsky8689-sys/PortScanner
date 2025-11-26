#ifndef PARSER_H 
#define PARSER_H

#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#include<ctype.h>

#define task_show_connections 1
#define task_scan 2
#define task_sniff 3
#define task_analyze 4
#define task_read 5
#define task_exit 6
#define DEFAULT_COMMAND task_scan
#define MIN_PORT 1
#define MAX_PORT 65535
#define MAX_CHARACTERS 50000
#define DEFAULT_TIMEOUT 1000
#define DEFAULT_MAX_CONCURRENT 100
#define APP_NAME "scanner"
#define AVAILIBLE_SCAN_TYPES "-tcp -udp"
#define WRONG_COMMAND_OUTPUT "Incorrect syntax type scanner -h or scanner --help for more\n"
#define WRONG_PORT_ERROR "1 <= FIRST PORT <= LAST PORT <= 65545\n"

#define HELP_OUTPUT "_________________Port Scanner_____________\nCommon usage patterns: scanner -host HOSTNAME -scan_type -first_port -last_port -timeout -max_concurrent_sockets\nscanner -tcp -first [number>=1] -last [number<=65535] -timeout [timeout in miliseconds] -max_concurrent_sockets [number<=1024]\nscanner -udp -first[number>=1] -last[number<=65535] -timeout[timeout in miliseconds] -max_concurrent_sockets [number<=1024]\n"
extern char availible[50][1000];
typedef struct parsed_input{
  int scan_type;//refference to worker's scan types
  char hostname[100];
  char type_scan[10];
  int first;
  int last;
  int timeout;
  int max_concurrent;
  int command_type;
}parsed_input;

extern struct parsed_input* prepare_result();
extern struct parsed_input* parse(char command[MAX_CHARACTERS]);
extern int has_command(char command[MAX_CHARACTERS]);
#endif
