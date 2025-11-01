#include "scanner.h"
int* first;
int* last;
char* hostname;
int* sockets;
int* epoll;
struct sockaddr_in* connections_data;
struct epoll_event* events;
int* last_index;
int* sockets_needed;

int compute_sockets_number(int first,int last){
  int rez=(last-first)/MAX_PORTS_PER_SOCKET;
  if((last-first)%MAX_PORTS_PER_SOCKET)rez++;
  return rez;
}
void process_end(sig_atomic_t signum){

   close_sockets(*first,*last);
   deallocate_data();
   exit(0);
}
int deallocate_data(){
  int remaining = 0;
  if(last_index)free(last_index);
  if(epoll)free(epoll);
  if(sockets_needed)free(sockets_needed);
  if(hostname)free(hostname);
  if(first)free(first);
  if(last)free(last);
  if(events)free(events);
  if(sockets)free(sockets);
  if(connections_data)free(connections_data);
  return -remaining;
}
int reallocate_data(int newsize){
  int* new_sockets = realloc(sockets,newsize*sizeof(int));
  if(!new_sockets){
     fprintf(stderr,"realloc new sockets():error %d",errno);
     return -1;
  }
  sockets=new_sockets;
  struct sockaddr_in* new_connection_data = realloc(connections_data,newsize*sizeof(struct sockaddr_in));
   if(!new_connection_data){
     fprintf(stderr,"realloc new connections data():error %d",errno);
     return -1;
  }
   connections_data=new_connection_data;
  struct epoll_event* new_events = realloc(events,newsize*sizeof(struct epoll_event));
   if(!new_events){
     fprintf(stderr,"realloc new events():error %d",errno);
     return -1;
  }
   events=new_events;
  return 0;
}
int allocate_data(){
  sockets_needed=malloc(sizeof(int));
  last_index=malloc(sizeof(int));
  epoll=malloc(sizeof(int));
  first=malloc(sizeof(int));
  last=malloc(sizeof(int));
  hostname=malloc(sizeof(char)*MAX_HOSTNAME_LENGTH);
  sockets=malloc(sizeof(int)*MAX_FD_PER_PROCESS);
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
  if(last>65365)last=*sockets_needed;

  for(int i=0;i<*sockets_needed;i++){
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
int close_epoll(){
   if(*epoll>0)close(*epoll);
   return *epoll;
}
int config_epoll(){
   *epoll=epoll_create1(EPOLL_CLOEXEC);
   if(*epoll<0){
      fprintf(stderr,"epoll_create() error: %d\n",errno);
      return -1;
   }
   for(int i=0;i<*sockets_needed;i++){
     events[i].events=EPOLLIN;
     events[i].data.fd=sockets[i];
     if(epoll_ctl(*epoll,EPOLL_CTL_ADD,sockets[i],&events[i])<0){
        fprintf(stderr,"Socket number %d couldn't be added due to error %d",i+1,errno);
	return -1;
     }
     if(listen(sockets[i],5)<0){
         fprintf(stderr,"listen sock nr %d error %d",i,errno);
	 return -1;
     }
   }
   return 0;
}
int run_epoll(){
   int n = epoll_wait(*epoll,events,256,-1);
   if(n<0){
      fprintf(stderr,"epoll wait() %d\n",errno);
   }
   for(int i=0;i<n;i++){
      
   }
   return 0;
}
int scan_specific_host(char* host){
        run_epoll();
	return 0;
}
int main(int argc,char** argv){
 signal(SIGINT,process_end);
 if(argc<4){
    fprintf(stderr,"usage ./scanner ip start end");
    _exit(1);
 }
 if(allocate_data()<0){
    fprintf(stderr,"allocate_data()");
    _exit(deallocate_data());
 }
 strcpy(hostname,argv[1]);
 *first=atoi(argv[2]);
 *last=atoi(argv[3]);
 *sockets_needed=compute_sockets_number(*first,*last);

 fprintf(stdout,"SOCKETS NEEDED:%d\n",*sockets_needed);
 if(*sockets_needed<=MAX_FD_PER_PROCESS){
	 if(*sockets_needed<MAX_FD_PER_PROCESS){
	     if(reallocate_data(*sockets_needed)<0)fprintf(stderr,"realloc()");
_exit(deallocate_data());
	 }
 }
 else{
    fprintf(stderr,"Fd limit of %d exceeded",MAX_FD_PER_PROCESS);
    _exit(deallocate_data());
 }
 if(prepare_sockets(*first,*last)<0){
    fprintf(stderr,"prepare_sockets()");
    _exit(deallocate_data());
 }
 if(config_epoll()<0){
    fprintf(stderr,"config_epoll()");
    close_sockets(*first,*last);
    _exit(deallocate_data());
 }
 scan_specific_host(hostname);
 return deallocate_data();
}
