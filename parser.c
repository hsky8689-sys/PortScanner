#include"parser.h"
char availible[50][1000] = {"scanner","-host","-tcp","-udp","-timeout","-first","-last","-maxc"};
char scan_types[50][1000] = {"tcp","udp","syn","xmas","null","fyn"};
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

int parse_syn_request(char command[MAX_CHARACTERS],struct parsed_input *res){
	char already_used[MAX_CHARACTERS];
	char last_arg[1000];

        ok_input = 1;
	res->command_type = 2;
	strcpy((char*)&res->scan_type,"syn");
	int words = split_command(command);
	int index = 0;
	
	if(strcmp(parsed_command[0],APP_NAME)){
	      ok_input = 0;
	      return ok_input;
	}
	index++;
	strcpy(last_arg,APP_NAME);
	strcat(already_used,APP_NAME);

	while(index < words && ok_input == 1){

		if((has_command(parsed_command[index]) == has_command(last_arg)) 
		   && strcmp(APP_NAME,last_arg)!=0){
			ok_input = 0;
			break;
		}

		if(has_command(parsed_command[index])){
		   if(strstr(already_used,parsed_command[index]))
			   ok_input = 0;
		}
		else{
		   if(strcmp(last_arg,"-host")==0){
		      	 strcpy(res->hostname,parsed_command[index]);
			 continue;
		   }
		   if(strcmp(last_arg,"-first")==0){
		        int len = strlen(parsed_command[index]);
		        for(int i=0;i<len && ok_input;i++)
			    if(parsed_command[index][i] < 48 || parsed_command[index][i] > 57)
			    ok_input = 0;
	 		int nr = atoi(last_arg);
			if(!ok_input) continue;
			if(nr < MIN_PORT || nr > MAX_PORT)
				ok_input = 0;
			res->first = nr;
			if(res->first > res->last)
		 		ok_input = 0;
			continue;		
		   }
		   if(strcmp(last_arg,"-last")==0){
                        int len = strlen(parsed_command[index]);
                        for(int i=0;i<len && ok_input;i++)
                            if(parsed_command[index][i] < 48 || parsed_command[index][i] > 57)
                            ok_input = 0;
                        if(!ok_input) continue;
			int nr = atoi(last_arg);
                        if(nr < MIN_PORT || nr > MAX_PORT)
                                ok_input = 0;
			res->last = nr;
			if(res->first > res->last)
				ok_input = 0;
			continue;
                   }


		}
		strcpy(last_arg,parsed_command[index]);
		index++;
	}
	if(strlen(res->hostname)==0)
		ok_input = 0;
	return ok_input;
}

struct parsed_input* parse(char command[MAX_CHARACTERS]){
	if(strlen(command)==0)return NULL;
	struct parsed_input *result = prepare_result();
	if(result==NULL)return NULL;

	for(int i=0;i<strlen(command);i++)
                command[i]=tolower(command[i]);
	//check scan type request(1 or 0 cant request -tcp -udp on the same scan)
	int words = split_command(command);
	for(int i=0;i<words;i++){
	   printf("%s\n",parsed_command[i]);
	}
	if(parse_syn_request(command,result)<0){
	    free(result);
	    return NULL;
	}
	return result;

	//idc tbh
	char last_arg[MAX_CHARACTERS];
	char already_used[MAX_CHARACTERS];
        
	for(int i=0;i<strlen(command);i++)
		command[i]=tolower(command[i]); //case insensitive
	
	command[strcspn(command,"\n")] = 0;
	
	if(!strstr(command,APP_NAME)){
	   fprintf(stdout,WRONG_COMMAND_OUTPUT);
	   
	   goto error;
	}

	if(strcmp(command,"scanner -h")==0||strcmp(command,"scanner -help")==0){
	 fprintf(stdout,HELP_OUTPUT);
	 
	 goto error;//not an error here :)
        }
        else{
	    char* word = strtok(command," \t");
	    strcpy(last_arg,word);
	    printf("Last arg:%s\n",last_arg);
	    word = strtok(NULL," ");

	   if(strcmp(last_arg,"scanner")!=0){
	       fprintf(stdout,HELP_OUTPUT);
	       
	       goto error;
	   }
           int protocol_specified = 0; 
           while(word!=NULL){
		fprintf(stdout,"Currently parsing word %s of length %ld\n",word,strlen(word));
		if(has_command(word)){
		    //fprintf(stdout,"Word %s is a command\n",word);
	            if(strcmp(last_arg,"scanner")!=0){
		      if(has_command(last_arg)&&!strstr(AVAILIBLE_SCAN_TYPES,last_arg)){
			 fprintf(stdout,HELP_OUTPUT);
			 
			 goto error;
		      }
		      if(strstr(already_used,word)){
			 fprintf(stdout,"You may only set an attribute command once\n");
			
			 goto error; 
		      }
		      if(strstr(AVAILIBLE_SCAN_TYPES,word)){
			 fprintf(stdout,"Word %s is a scan protocol\n",word);
			 if(protocol_specified){
                           fprintf(stdout,"A single scan uses ONE of the availible protocols %s\n",AVAILIBLE_SCAN_TYPES);
                    
			   goto error;
                         }
			 else{ 
				 protocol_specified=1;
			         strcpy(result->type_scan,word+1);
				 fprintf(stdout,"Scan protocol set to %s\n",result->type_scan);
			 }
		      }
		      strcat(already_used,word);
		   }
		   else{
		      if(strstr(AVAILIBLE_SCAN_TYPES,word)){
                         fprintf(stdout,"Word %s is a scan protocol\n",word);
                         if(protocol_specified){
                           fprintf(stdout,"A single scan uses ONE of the availible protocols %s\n",AVAILIBLE_SCAN_TYPES);
			    goto error; 
                         }else{
			    protocol_specified = 1;
			    fprintf(stdout,"Scan protocol is set to %s\n",word);
			 }
                    strcat(already_used,word);
		   }
                }
		}
		else
	        {
			if(strcmp(last_arg,"-host")==0){
			   if(strlen(result->hostname)>0){
			       fprintf(stdout,"Can only scan one host\n");
			       goto error;
			   }
			   strcpy(result->hostname,word);
			}
			else if(strcmp(last_arg,"-first")==0){
			   int first = atoi(word);
			   if(first<MIN_PORT||first>MAX_PORT||first>result->last){
			      fprintf(stdout,"1 <= FIRST PORT <= LAST PORT <= 65535\n");
			      
			      goto error;
			   }
			   result->first=first;
			}
			else if(strcmp(last_arg,"-last")==0){
			   int last = atoi(word);
			   if(last<MIN_PORT||last>MAX_PORT||last<result->first){
                              fprintf(stdout,"1 <= FIRST PORT <= LAST PORT <= 65535\n");
                               
			      goto error;
                           }
			   result->last=last;
			}
			else if(strcmp(last_arg,"-timeout")==0){
			    int timeout = atoi(word);
			    if(timeout<0){
			       fprintf(stdout,"TIMEOUT > 0\n");
			       
			       goto error; 
			    }
			    result->timeout=timeout;
			}
			else if(strcmp(last_arg,"-maxc")==0){
			    int maxc = atoi(word);
			    if(maxc<0){
			      fprintf(stdout,"NR OF CONCURRENT SOCKETS > 0"); 
			    
			    
			     goto error;
			    }
			    result->max_concurrent=maxc;
			}
			else{
			  if(has_command(last_arg)==has_command(last_arg)){
			     fprintf(stdout,HELP_OUTPUT);
			      
			     goto error;
			  }
			}

		}
		strcpy(last_arg,word);
		word = strtok(NULL," \t");
	    }
        }
	if(strcmp(result->hostname,"")==0){
	   fprintf(stdout,"You need to specify a hostname to scan\n");
	}
	if(strcmp(result->type_scan,"")==0){
	   fprintf(stdout,"You need to specify a scan protocol from the availible %s\n",AVAILIBLE_SCAN_TYPES);
	}
goto ok;	
error:

ok:
	return result;
}
