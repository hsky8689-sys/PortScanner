#include "scanner.h"
int* first;
int* last;
char* hostname;
int* sockets;
int* epoll;
struct sockaddr_in* connections_data;

void process_end(sig_atomic_t signum){

   close_sockets(*first,*last);
   deallocate_data();
   exit(0);
}
int deallocate_data(){
  int remaining = 0;
  if(epoll)free(epoll);
  if(hostname)free(hostname);
  if(first)free(first);
  if(last)free(last);
  if(sockets)free(sockets);
  if(connections_data)free(connections_data);
  return -remaining;
}
int allocate_data(){
  epoll=malloc(sizeof(int));
  first=malloc(sizeof(int));
  last=malloc(sizeof(int));
  hostname=malloc(sizeof(char)*MAX_HOSTNAME_LENGTH);
  sockets=malloc(sizeof(int)*MAX_FD_PER_PROCESS);
  connections_data=malloc(sizeof(struct sockaddr_in)*MAX_FD_PER_PROCESS);
  return (epoll && first && last && hostname && connections_data && sockets)-1;
}
int close_sockets(int first,int last){
  fprintf(stdout,"%d %d",first,last);
  for(int i=0;i<=last-first;i++){
     close(sockets[i]);
  }
  close(*epoll);
   return 0;
}

int prepare_sockets(int first,int last){
  if(first<0)first=0;
  if(last>65365)last=65365;
  *epoll=epoll_create(last-first+1);

  for(int i=0;i<=last-first;i++){
    sockets[i]=socket(AF_INET,SOCK_STREAM,0);
    if(sockets[i]<0){
      fprintf(stderr,"Could not initialize socket number %d\n",i+1);
      close_sockets(0,i);
      return -1;
    }
    int flags = fcntl(sockets[i],F_GETFL,0);
    if (flags<0){
	    fprintf(stderr,"Could not get the flags of the socket number %d\n",i+1);
    }
    if(fcntl(sockets[i],F_SETFL,flags|SOCK_NONBLOCK)<0){
	    fprintf(stderr,"Error setting socket number %d as non-blocking\n",i+1);
    }
    else{
	    connections_data[i].sin_family=AF_INET;
	    connections_data[i].sin_port=htons(i+first);
	    connections_data[i].sin_addr.s_addr=INADDR_ANY;
            if (bind(sockets[i],(struct sockaddr*)&connections_data[i],sizeof(connections_data[i]))<0){
	       fprintf(stderr,"Could not bind socket number %d\n",i+1);
	       close_sockets(0,i);
	       return -1;
	    }
    }
  }
  return 0;
}
void scan_specific_host(char* hostname,int first,int last){
 // (void)hostname;void(first);void(last);
  fprintf(stdout,"%s %d %d",hostname,first,last);
}
int main(int argc,char** argv){
 signal(SIGINT,process_end);
 if(argc<4){
       fprintf(stderr,"Usage: ./scanner hostname first port last port");
    }
    if(allocate_data()<0){
       fprintf(stderr,"Enviroment could not be set up");
       exit(deallocate_data());
    }
    strcpy(hostname,argv[1]);
    *first=atoi(argv[2]);
    *last=atoi(argv[3]);
    if(prepare_sockets(*first,*last)<0){
       fprintf(stderr,"Could not prepare sockets for scanning");
       exit(deallocate_data());
    }
    fprintf(stdout,"HOST:%s FIRST:%d LAST:%d",hostname,*first,*last); 
    return deallocate_data();
}
