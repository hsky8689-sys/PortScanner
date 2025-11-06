#include "scanner.h"
int* first;
int* last;
char* hostname;
int* sockets;
int* epoll;
struct sockaddr_in* connections_data;
struct epoll_event* events;
struct epoll_event* recieve_data;
int* last_index;
int* sockets_needed;
range* ranges;
int result[MAX_FD_PER_PROCESS];
int scan_tcp_port(int sock_index){
	if(sockets[sock_index]<0){
	  fprintf(stderr,"Invalid socket");
	  return -1;
	}
	if(ranges[sock_index].first>=ranges[sock_index].last){
	  fprintf(stderr,"All ports assigned to %d have been scanned\n",sock_index);
	  return -1;
	}
	if(sock_index<*first||sock_index>*last){
	  fprintf(stderr,"Invalid socket index");
	  return -1;
	}
	socklen_t len = sizeof(connections_data[sock_index]);
	if(bind(sockets[sock_index],(struct sockaddr*)&connections_data[sock_index],len)<0){
	  fprintf(stderr,"Could not bind socket");
	  return -1;
	}
	if(listen(sockets[sock_index],1)<0){
	  fprintf(stderr,"Could not make socket listen");
	  return -1;
	}
	int c = connect(sockets[sock_index],(struct sockaddr*)&connections_data[sock_index],len);
        switch(c){
	   case -1:{
	      fprintf(stderr,"Error %d occured\n",errno);
              return -1;	      
            }
	    case 0:{
			 return 0;
	    }
            default:{
		    fprintf(stderr,"....\n");
		    return -2;
		    }
	}
}
int compute_sockets_number(int first,int last){
  int rez=(last-first)/MAX_PORTS_PER_SOCKET;
  if((last-first)%MAX_PORTS_PER_SOCKET)rez++;
  return rez;
}
void process_end(sig_atomic_t signum){
	close_sockets(*first,*last);
	close_epoll();
	_exit(deallocate_data());                                          
}   
int deallocate_data(){
  if(last_index)free(last_index);
  if(epoll)free(epoll);
  if(sockets_needed)free(sockets_needed);
  if(hostname)free(hostname);
  if(first)free(first);
  if(last)free(last);
  if(events)free(events);
  if(sockets)free(sockets);
  if(recieve_data)free(recieve_data);
  if(connections_data)free(connections_data);
  if(ranges)free(ranges);
  return (!ranges && !recieve_data && !last_index && !epoll && !sockets && !hostname && !events && !sockets && !connections_data)-1;
}
int reallocate_data(int newsize){
  range* new_ranges = realloc(ranges,newsize*sizeof(range));
  if(!new_ranges){
     fprintf(stderr,"realloc new ranges():error %d",errno);
     return -1;
  }
  int* new_sockets = realloc(sockets,newsize*sizeof(int));
  if(!new_sockets){
     fprintf(stderr,"realloc new sockets():error %d",errno);
     return -1;
  }
  sockets=new_sockets;
  struct epoll_event* new_recieve_data = realloc(recieve_data,newsize*sizeof(struct epoll_event));
  if(!new_recieve_data){
     fprintf(stderr,"realloc new recieve data():error %d",errno);
     return -1;
  }
  recieve_data=new_recieve_data;
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
int allocate_data(char* begin,char* end){
  sockets_needed=malloc(sizeof(int));
  last_index=malloc(sizeof(int));
  epoll=malloc(sizeof(int));
  first=malloc(sizeof(int));
  last=malloc(sizeof(int));
  hostname=malloc(sizeof(char)*MAX_HOSTNAME_LENGTH);
  
  *first=atoi(begin);
  *last=atoi(end);
  *sockets_needed=compute_sockets_number(*first,*last);
  
  ranges=malloc(sizeof(range)*(*sockets_needed));
  sockets=malloc(sizeof(int)*(*sockets_needed));
  events=malloc(sizeof(struct epoll_event)*(*sockets_needed));
  connections_data=malloc(sizeof(struct sockaddr_in)*(*sockets_needed));
  return (epoll && first && last && hostname && connections_data && sockets && events)-1;
}
int close_sockets(int first,int last){
  if(first<0)first=0;
  if(last>65365)last=65365;
  for(int i=0;i<*sockets_needed;i++){
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
int prepare_sockets(){
  for(int i=0;i<*sockets_needed;i++){
     sockets[i]=socket(AF_INET,SOCK_STREAM,0);
     if(sockets[i]<0){
        fprintf(stderr,"socket() number %d| error %d\n",i,errno);
        close_sockets(0,i);
     }
     if(config_socket(i,i*MAX_PORTS_PER_SOCKET)<0){
        fprintf(stderr,"config_socket() number %d|error %d\n",i,errno);
     }
     ranges[i].first=i*MAX_PORTS_PER_SOCKET;
     ranges[i].last=MIN((i+1)*MAX_PORTS_PER_SOCKET,*last);
     fprintf(stdout,"Socket %d scanning ports %d-%d\n",i,ranges[i].first,ranges[i].last);
  }
  return 0;
}
int close_epoll(){
   if(*epoll>0)close(*epoll);
   printf("epoll now:%d\n",*epoll);
   return *epoll;
}
int config_epoll(){
   *epoll=epoll_create1(EPOLL_CLOEXEC);
   if(*epoll<0){
      fprintf(stderr,"epoll_create() error: %d\n",errno);
      return -1;
   }
   for(int i=0;i<*sockets_needed;i++){
      events[i].data.fd=sockets[i];
      events[i].events=EPOLLIN;
      if(epoll_ctl(*epoll,EPOLL_CTL_ADD,sockets[i],&events[i])<0){
        fprintf(stderr,"Could not add socket[%d] to epoll\n error %d",i,errno);
      }
   }
   return 0;
}
int run_epoll(){
    int currentfd=events[0].data.fd;
    int left_unscanned=*last-*first+1;
     while(left_unscanned){
       int n = epoll_wait(*epoll,events,*sockets_needed,-1);
       for(int i=0;i<n;i++)
	       if(events[i].data.fd==currentfd)
	       {
		       printf("Detected event");
		       printf("Socket %d scanning port %d\n...",i,ranges[i].first);
		       result[ranges[i].first]=scan_tcp_port(i);
		       left_unscanned--;
	       }
	       else{
	          currentfd=events[i].data.fd;
		  if(config_socket(i,ranges[i].first+1)<0){
		     fprintf(stderr,"Porturile socket-ului %d au fost scanate\n",i);
		  }
		  else{
		     epoll_ctl(*epoll,EPOLL_CTL_ADD,currentfd,&events[i]);
		  }
	       }
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
 if(allocate_data(argv[2],argv[3])<0){
    fprintf(stderr,"allocate_data()");
    _exit(deallocate_data());
 }
 strcpy(hostname,argv[1]);

 fprintf(stdout,"SOCKETS NEEDED:%d\n",*sockets_needed);
 if(*sockets_needed>MAX_FD_PER_PROCESS){
 /*        if(*sockets_needed<MAX_FD_PER_PROCESS){
		 if(reallocate_data(*sockets_needed)<0){
	          fprintf(stderr,"realloc()");
                  _exit(deallocate_data());}
         }
 }*/

    fprintf(stderr,"Fd limit of %d exceeded",MAX_FD_PER_PROCESS);
    _exit(deallocate_data());
 }

 if(prepare_sockets(*first,*last)<0){
    fprintf(stderr,"prepare_sockets()");
    _exit(deallocate_data());
 }
 config_epoll();
 scan_specific_host(hostname);
 close_epoll();
 close_sockets(*first,*last);
 return deallocate_data();
}
