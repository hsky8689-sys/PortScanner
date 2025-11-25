#include"parser.h"
int has_command(char command[]){
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
   result->first=MIN_PORT;
   result->last=MAX_PORT;
   result->timeout=DEFAULT_TIMEOUT;
   result->max_concurrent=DEFAULT_MAX_CONCURRENT;
   return result;
}
struct parsed_input* parse(char command[]){
	if(strlen(command)==0)return NULL;
	struct parsed_input *result=prepare_result();
	char* last_arg = malloc(100*sizeof(char));
	strcpy(last_arg,"");
	char* already_used = malloc(100*sizeof(char)); 
	if(last_arg==NULL||already_used==NULL){
	   perror("malloc");
	   free(result);
	   if(last_arg)free(last_arg);
	   if(already_used)free(already_used);
	   return NULL;
	}
	for(int i=0;i<strlen(command);i++)
		command[i]=tolower(command[i]); //case insensitive
	
	command[strcspn(command,"\n")] = 0;
	if(!strstr(command,APP_NAME)){
	   fprintf(stdout,WRONG_COMMAND_OUTPUT);
	   free(result);
	   free(last_arg);
	   free(already_used);
	   return NULL;
	}

	if(strcmp(command,"scanner -h")==0||strcmp(command,"scanner -help")==0){
	 fprintf(stdout,HELP_OUTPUT);
	 free(result);
	 free(already_used);
	 free(last_arg);
	 return NULL;
        }
        else{
	    char* word = strtok(command," \t");
	    strcpy(last_arg,word);
	    printf("Last arg:%s\n",last_arg);
	    word = strtok(NULL," ");

	   if(strcmp(last_arg,"scanner")!=0){
	       fprintf(stdout,HELP_OUTPUT);
	       free(result);
	       free(already_used);
	       free(last_arg);
	       return NULL;
	   }
           int protocol_specified = 0; 
           while(word!=NULL){
		fprintf(stdout,"Currently parsing word %s of length %ld\n",word,strlen(word));
		if(has_command(word)){
		    //fprintf(stdout,"Word %s is a command\n",word);
	            if(strcmp(last_arg,"scanner")!=0){
		      if(has_command(last_arg)&&!strstr(AVAILIBLE_SCAN_TYPES,last_arg)){
			 fprintf(stdout,HELP_OUTPUT);
			 free(result);
			 free(last_arg);
			 free(already_used);
			 return NULL;
		      }
		      if(strstr(already_used,word)){
			 fprintf(stdout,"You may only set an attribute command once\n");
			 free(result);                                                                                           free(last_arg);                                                                                         free(already_used);                                                                                     return NULL; 
		      }
		      if(strstr(AVAILIBLE_SCAN_TYPES,word)){
			 fprintf(stdout,"Word %s is a scan protocol\n",word);
			 if(protocol_specified){
                           fprintf(stdout,"A single scan uses ONE of the availible protocols %s\n",AVAILIBLE_SCAN_TYPES);
                           free(result);                                                                                           free(last_arg);                                                                                         free(already_used);                                                                                     return NULL; 
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
                            free(result);                                                                                           free(last_arg);                                                                                         free(already_used);                                                                                     return NULL; 
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
			   strcpy(result->hostname,word);
			}
			else if(strcmp(last_arg,"-first")==0){
			   int first = atoi(word);
			   if(first<MIN_PORT||first>MAX_PORT||first>result->last){
			      fprintf(stdout,"1 <= FIRST PORT <= LAST PORT <= 65535\n");
			      free(result);                                                                                           free(last_arg);                                                                                         free(already_used);                                                                                     return NULL; 
			   }
			   result->first=first;
			}
			else if(strcmp(last_arg,"-last")==0){
			   int last = atoi(word);
			   if(last<MIN_PORT||last>MAX_PORT||last<result->first){
                              fprintf(stdout,"1 <= FIRST PORT <= LAST PORT <= 65535\n");
                              free(result);                                                                                           free(last_arg);                                                                                         free(already_used);                                                                                     return NULL; 
                           }
			   result->last=last;
			}
			else if(strcmp(last_arg,"-timeout")==0){
			    int timeout = atoi(word);
			    if(timeout<0){
			       fprintf(stdout,"TIMEOUT > 0\n");
			       free(result);                                                                                           free(last_arg);                                                                                         free(already_used);                                                                                     return NULL; 
			    }
			    result->timeout=timeout;
			}
			else if(strcmp(last_arg,"-maxc")==0){
			    int maxc = atoi(word);
			    if(maxc<0){
			      fprintf(stdout,"NR OF CONCURRENT SOCKETS > 0");
			      free(result);                                                                                           free(last_arg);                                                                                         free(already_used);                                                                                     return NULL; 
			    }
			    result->max_concurrent=maxc;
			}
			else{
			  if(has_command(last_arg)==has_command(last_arg)){
			     fprintf(stdout,HELP_OUTPUT);
			     free(result);                                                                                           free(last_arg);                                                                                         free(already_used);                                                                                     return NULL; 
			  }
			}

		}
		strcpy(last_arg,word);
		word = strtok(NULL," \t");
	    }
        }
	if(strcmp(result->hostname,"")==0){
	   fprintf(stdout,"You need to specify a hostname to scan\n");
	   if(result)free(result);
	}
	if(strcmp(result->type_scan,"")==0){
	   fprintf(stdout,"You need to specify a scan protocol from the availible %s\n",AVAILIBLE_SCAN_TYPES);
	   if(result)free(result);
	}
	if(result)free(result);
	if(last_arg)free(last_arg);
	if(already_used)free(already_used);
	return result;
}
int main(){
    char command[MAX_CHARACTERS];
    //while(1){
            fgets(command,sizeof(command),stdin);
	    parse(command);
        // }
}
