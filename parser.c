#include"parser.h"
char availible[50][1000] = {"scanner","-host","-tcp","-udp","-timeout","-first","-last","-maxc"};
char scan_types[50][1000] = {"-tcp","-udp","-syn","-xmas","-null","-fyn"};
char parsed_command[50][1000];
int ok_input;
int has_command(char* command){
   for(int i=0;i<8;i++){
     if(strcmp(command,availible[i])==0)return 1;
   }
   return 0;
}
struct parsed_input* prepare_result(){
   struct parsed_input *result=malloc(sizeof(struct parsed_input));
   if(result==NULL){
      perror("malloc");
      return NULL;
   }
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
        char already_used[MAX_CHARACTERS];
        char last_arg[1000];

        ok_input = 1;
        res->command_type = 2;

        int words = split_command(command);
        int index = 0;

        if(strcmp(parsed_command[0],APP_NAME)){
              ok_input = 0;
              fprintf(stdout,"n-are numele aplicatiei\n");
              return ok_input;
        }
        index++;
        strcpy(last_arg,APP_NAME);
        strcat(already_used,APP_NAME);

        while(index < words){
/*
                if((has_command(parsed_command[index]) == has_command(last_arg)) && strcmp(APP_NAME,last_arg)!=0){
                        ok_input = 0;
                        fprintf(stdout,"2 comenzi/noncomenzi\n");
                        break;
                }*/

                if(has_command(parsed_command[index])){
                   if(strstr(already_used,parsed_command[index])){
                           ok_input = 1;

                           fprintf(stdout,"duplicata %s\n",parsed_command[index]);
                           return ok_input;
                	}
		}
                else{
                   for(int i=0;i<6;i++){
                      if(strcmp(parsed_command[index],scan_types[i])==0){
                            if(strcmp(res->type_scan,"")!=0){
                                 ok_input = 0;
                                 fprintf(stdout,"2 tipuri de scan %s %s\n",res->type_scan,parsed_command[index]);

                            }
                            else {
                                    strncpy(parsed_command[index],res->type_scan,strlen(parsed_command[index]));

                            }

                      }
                   }
                   if(strcmp(last_arg,"-host")==0){
                         strcpy(res->hostname,parsed_command[index]);
                       
                   }
                   else if(strcmp(last_arg,"-first")==0){
                        int len = strlen(parsed_command[index]);
                        for(int i=0;i<len && ok_input;i++)
                            if(parsed_command[index][i] < 48 || parsed_command[index][i] > 57)
                            ok_input = 0;
                        int nr = atoi(last_arg);
                        if(!ok_input) goto nonnumeric;
                        if(nr < MIN_PORT || nr > MAX_PORT)
                                ok_input = 0;
                        res->first = nr;
                        if(res->first > res->last)
                                ok_input = 0;
nonnumeric:

                   }
                   else if(strcmp(last_arg,"-last")==0){
                        int len = strlen(parsed_command[index]);
                        for(int i=0;i<len && ok_input;i++)
                            if(parsed_command[index][i] < 48 || parsed_command[index][i] > 57)
                            ok_input = 0;
                        if(!ok_input) goto nonnumeric2;
                        int nr = atoi(last_arg);
                        if(nr < MIN_PORT || nr > MAX_PORT)
                                ok_input = 0;
                        res->last = nr;
                        if(res->first > res->last)
                                ok_input = 0;
nonnumeric2:
                   }


                }
                strcpy(last_arg,parsed_command[index]);
                index++;
        }
        if(strlen(res->hostname)==0){
                fprintf(stdout,"host gol\n");
                ok_input = 0;
        }
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

    // check scan type request (nu permiți -tcp și -udp simultan)
    if (parse_scan_request(command, result) == 0){
	    fprintf(stdout,"result = null");
//	    free(result);
    }
    
    return result;
}

