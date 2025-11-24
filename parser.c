#include"parser.h"
int has_command(char command[]){
   for(int i=0;i<6;i++){
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
	if(last_arg==NULL){
	   perror("malloc");
	   free(result);
	   return NULL;
	}
	for(int i=0;i<strlen(command);i++)
		command[i]=tolower(command[i]); //case insensitive
	
	command[strcspn(command,"\n")] = 0;
	if(!strstr(command,APP_NAME)){
	   fprintf(stdout,WRONG_COMMAND_OUTPUT);
	   free(result);
	   return NULL;
	}
	else{
	  if(strcmp(command,"scanner -h")==0||strcmp(command,"scanner -help")==0){
		  fprintf(stdout,HELP_OUTPUT);
		  free(result);
		  return NULL;
	  }
	  else{
	    char* word = strtok(command," \t");
	    word = strtok(NULL," ");

	    while(word!=NULL){
	        if(has_command(word)){
		   	   printf("comanda\n");
			   strcpy(last_arg,word);
		}
		else{
	            if(!has_command(last_arg)){
		       free(last_arg);
		       free(result);
		       fprintf(stdout,HELP_OUTPUT);
		       return NULL;
		    }
		    printf("argument");	
		    if(strcmp(word,"scanner")!=0){
		       if(strcmp(last_arg,AVAILIBLE_SCAN_TYPES)==0){
		          free(last_arg);
			  free(result);
			  fprintf(stdout,HELP_OUTPUT);
			  return NULL;
		     }
		       else if(strcmp(last_arg,"-first")==0){
			  int first = atoi(word);
			  if(result->first!=MIN_PORT||result->first<1||result->first>65535||result->first>result->last||first<MIN_PORT||first>MAX_PORT){
			     free(last_arg);
			     free(result);
			     fprintf(stdout,WRONG_PORT_ERROR);
			     fprintf(stdout,HELP_OUTPUT);
			     return NULL;
			  }
			  result->first=first;
		     }
		     else  if(strcmp(last_arg,"-last")==0){
			  int last = atoi(word);
                          if(result->last!=MAX_PORT||result->last<1||result->last>65535||result->first>result->last<MIN_PORT||last>MAX_PORT){
                             free(last_arg);
                             free(result);
                             fprintf(stdout,WRONG_PORT_ERROR);
                             fprintf(stdout,HELP_OUTPUT);
                             return NULL;
                          }
		     else if(strcmp(last_arg,"-timeout")==0){
		             if(result->timeout!=DEFAULT_TIMEOUT);
		           }  
			  result->last = last;
                       }

		    }
		}
		strcpy(last_arg,word);
	        word = strtok(NULL," \t");
	    }
	  }
	   
	}
	free(last_arg);
	return result;
}
int main(){
    char command[MAX_CHARACTERS];
	while(1){
            fgets(command,sizeof(command),stdin);
	    parse(command);
         }
}
