#include"parser.h"
char availible[50][1000] = {"scanner","-host","-tcp","-udp","-syn","-xmas","-null","-fyn","-timeout","-first","-last","-maxc"};
char scan_types[50][1000] = {"-tcp","-udp","-syn","-xmas","-null","-fyn"};
char parsed_command[50][1000];
int ok_input;
int has_command(char command[]){
   for(int i=0;i<8;i++){
     if(strcmp(command,availible[i])==0)
             return 1;
   }
   return 0;
}
struct parsed_input* prepare_result(){
   struct parsed_input *result=malloc(sizeof(struct parsed_input));
   if(result==NULL){
      perror("malloc");
      return NULL;
   }
   memset(result,0,sizeof(struct parsed_input));
   strcpy(result->hostname,"");
   strcpy(result->type_scan,"");
   result->command_type = DEFAULT_COMMAND;
   result->first=MIN_PORT;
   result->last=MAX_PORT;
   result->timeout=DEFAULT_TIMEOUT;
   result->max_concurrent=DEFAULT_MAX_CONCURRENT;
   return result;
}

int split_command(char command[MAX_CHARACTERS]){
    if(strlen(command)==0)return 0;
    char* word = strtok(command," ");
    int index = 0;
    while(word != NULL){
            strcpy(parsed_command[index],word);
           
            word = strtok(NULL," ");
            index ++;
    }
    return index;
}

int parse_scan_request(char command[MAX_CHARACTERS],struct parsed_input *res){
        ok_input = 1;
        res->command_type = task_scan;

        int words = split_command(command);

        int index = 0;

        if(strcmp(parsed_command[0],APP_NAME)){
              ok_input = 0;
              
              return ok_input;
        }
        fprintf(stdout,"words:=%d\n",words);
        for(int i=1;i<words;i++){
            if(!strcmp(parsed_command[i],"-host")){
                if(i+1 <= words){
                 strncpy(res->hostname,parsed_command[i+1],strlen(parsed_command[i+1]));
                 i++;
                }
                else ok_input = 0;
            }
            else if(strstr(AVAILIBLE_SCAN_TYPES,parsed_command[i])){
                  strncpy(res->type_scan,parsed_command[i],strlen(parsed_command[i]));
            }
            else if(strcmp(parsed_command[i],"-last") == 0 || strcmp(parsed_command[i],"-first") == 0)
                 {
                   if(i+1 < words){
                        int len = strlen(parsed_command[index]);
                        if(len==0){
                           ok_input = 0;
                           fprintf(stdout,"After either of '-first' or '-last' you need to specify a port number or the default 1,65365 will be set\n");
                        }
                        for(int j=0;j<len && ok_input;j++)
                            if(strchr("0123456789",parsed_command[i+1][j])==0){
                                    fprintf(stdout,"Non-letter in port number\n");
                                    ok_input = 0;
                            }
                        if(ok_input){
                            if(!strcmp(parsed_command[i],"-last")){
                                int last = atoi(parsed_command[i+1]);
                                if(last < res->first || last > MAX_PORT || last < MIN_PORT){
                                fprintf(stdout,"%d causes last < res->first || last > MAX_PORT || last < MIN_PORT\n",last);
                                        ok_input = 0;
                                }
                                else res->last = last,i++;
                            }
                            else{
                                int first = atoi(parsed_command[i+1]);
                                if(res->last < first || first < MIN_PORT || first > MAX_PORT){
                                        fprintf(stdout,"%d causes res->last < first || first < MIN_PORT || first > MAX_PORT\n",first);
                                        ok_input = 0;
                                }
                                else res->first = first,i++;
                            }
                        }

                   }
                   else {
                          ok_input = 0;
                          fprintf(stdout,"After either of '-first' or '-last' you need to specify a port number or the default 1,65365 will be set\n");
                   }
                  }
                  else if(strcmp(parsed_command[i],"-timeout")==0){
                          if(i+1<words){                                                                                                                                                 int len = strlen(parsed_command[i]);                                                                                                                        if(len==0){                                                                                                                                                     ok_input = 0;                                                                                                                                               fprintf(stdout,"After '-timeout' you need to specify a greater than zero number of miliseconds or the default %d will be set\n",DEFAULT_TIMEOUT);                                                                                                                                                                   }                                                                                                                                                           for(int j=0;j<len && ok_input;j++)                                                                                                                              if(strchr("0123456789",parsed_command[i+1][j])==0){                                                                                                             fprintf(stdout,"Non-letter in timeout number\n");                                                                                                           ok_input = 0;                                                                                                                                           }                                                                                                                                                       if(ok_input){                                                                                                                                                       res->timeout = atoi(parsed_command[i+1]);                                                                                                                   i += 1;                                                                                                                                             }                                                                                                                                                        }                                                                                                                                                           else {                                                                                                                                                          ok_input = 0;                                                                                                                                               fprintf(stdout,"After '-timeout' you need to specify a greater than zero number of miliseconds or the default %d will be set\n",DEFAULT_TIMEOUT);                                                                                                                                                                   }                                                                                                                                                    }
	}
        //fprintf(stdout,"HOSTNAME:%s\nSCAN TYPE:%s\nSTARTING PORT:%d\nFINAL PORT:%d\n%d\n %d\n",res->hostname,
          //        res->type_scan,res->first,res->last,res->max_concurrent,res->timeout);
        return ok_input;
}

struct parsed_input* parse(char command[MAX_CHARACTERS]) {
    size_t len = strlen(command);
    if (len == 0)
        return NULL;

    struct parsed_input *result = prepare_result();
    if (result == NULL)
        return NULL;

    for (size_t i = 0; i < len; i++) {
        command[i] = (char)tolower((unsigned char)command[i]);
    }

    return result;
}
