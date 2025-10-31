#include "scanner.h"
int* first;
int* last;
char* hostname;
int* sockets;
int* epoll;
struct sockaddr_in* connections_data;
struct epoll_event* events;

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
  if(events)free(events);
  if(sockets)free(sockets);
  if(connections_data)free(connections_data);
  return -remaining;
}
int allocate_data(){
  epoll=malloc(sizeof(int));
  first=malloc(sizeof(int));
  last=malloc(sizeof(int));
  hostname=malloc(sizeof(char)*MAX_HOSTNAME_LENGTH);
  sockets=malloc(sizeof(int)*SOCKETS_NUMBER);
  events=malloc(sizeof(struct epoll_event)*MAX_FD_PER_PROCESS);
  connections_data=malloc(sizeof(struct sockaddr_in)*MAX_FD_PER_PROCESS);
  return (epoll && first && last && hostname && connections_data && sockets && events)-1;
}
int close_sockets(int first,int last){
  if(first<0)first=0;
  if(last>65365)last=65365;
  for(int i=0;i<=last-first;i++){
	  if(sockets[i]>0)close(sockets[i]);
  }
  if(*epoll>0)close(*epoll);
  return 0;
}
int config_socket(int sock_index,int port){
    if(sockets[sock_index]<0){
       fprintf(stderr,"Invalid socket at index %d\n",sock_index);
       return -1;
    }
    if(port<*first || port>*last){
       fprintf(stderr,"Invalid port number requested\n");
       return -1;
    }
    int flags = fcntl(sockets[sock_index],F_GETFL,0);
    if(flags<0){
            fprintf(stderr,"Could not get the flags of the socket number %d\n",sock_index+1);
    }
    else if(fcntl(sockets[sock_index],F_SETFL,flags|SOCK_NONBLOCK)<0){
       fprintf(stderr,"Error setting socket number %d as non-blocking\n",sock_index+1);
    }
    memset(&connections_data[sock_index],0,sizeof(connections_data[sock_index]));
    connections_data[sock_index].sin_family=AF_INET;
    connections_data[sock_index].sin_port=port;
    connections_data[sock_index].sin_addr.s_addr=inet_addr(hostname);
    return 0;
}
int prepare_sockets(int first,int last){
  if(first<0)first=0;
  if(last>65365)last=65365;
  for(int i=0;i<last;i+=MAX_PORTS_PER_SOCKET){
     sockets[i]=socket(AF_INET,SOCK_STREAM,0);
     if(sockets[i]<0){
        fprintf(stderr,"socket() number %d| error %d\n",i,errno);
	close_sockets(0,i);
     }
     if(config_socket(i,i*MAX_PORTS_PER_SOCKET)<0){
        fprintf(stderr,"config_socket() number %d|error %d\n",i,errno);
     }
  }
  return 0;
}
void scan_specific_host(char* hostname,int first,int last){
  fprintf(stdout,"%s %d %d",hostname,first,last);
}
int main(int argc,char** argv){
 signal(SIGINT,process_end);
 if(argc<4){
       fprintf(stderr,"Usage: ./scanner hostname first_port last_port");
    }
    if(allocate_data()<0){
       fprintf(stderr,"Enviroment could not be set up");
       exit(deallocate_data());
    }
    strcpy(hostname,argv[1]);
    *first=atoi(argv[2])-atoi(argv[2]);
    *last=atoi(argv[3])-atoi(argv[2]);
    if(*last-*first>MAX_FD_PER_PROCESS){
        fprintf(stderr,"Cannot initialize more than %d sockets per process",MAX_FD_PER_PROCESS);
	exit(deallocate_data());
    }
    if(prepare_sockets(*first,*last)<0){
       fprintf(stderr,"Could not prepare sockets for scanning\n");
       exit(deallocate_data());
    }
    fprintf(stdout,"HOST:%s FIRST:%d LAST:%d",hostname,*first,*last); 
    return deallocate_data();
}
