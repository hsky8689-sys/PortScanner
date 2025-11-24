#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#include<ctype.h>

#define MIN_PORT 1
#define MAX_PORT 65365
#define MAX_CHARACTERS 50000
#define DEFAULT_TIMEOUT 1000
#define DEFAULT_MAX_CONCURRENT 100
#define APP_NAME "scanner"
#define AVAILIBLE_SCAN_TYPES "tcp|udp"
#define WRONG_COMMAND_OUTPUT "Incorrect syntax type scanner -h or scanner --help for more\n"
#define WRONG_PORT_ERROR "1 <= FIRST PORT <= LAST PORT <= 65545\n"
#define HELP_OUTPUT "_________________Port Scanner_____________\nCommon usage patterns: scanner -scan_type -first_port -last_port -timeout -max_concurrent_sockets\nscanner -tcp -first [number>=1] -last [number<=65535] -timeout [timeout in miliseconds] -max_concurrent_sockets [number<=1024]\nscanner -udp -first[number>=1] -last[number<=65535] -timeout[timeout in miliseconds] -max_concurrent_sockets [number<=1024]\n"
char availible[50][1000] = {"-tcp","-udp","-timeout","-first","-last","-max_concurrent_sockets"};
typedef struct parsed_input{
  char hostname[100];
  char type_scan[10];
  int first;
  int last;
  int timeout;
  int max_concurrent;
}parsed_input;

extern parsed_input* prepare_result();
extern parsed_input* parse(char command[MAX_CHARACTERS]);
extern int has_command(char command[]);
