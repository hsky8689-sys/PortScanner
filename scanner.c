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
	  fprintf(stderr,"Invalid socket\n");
	  return -1;
	}
	fprintf(stdout,"first:%d last:%d\n",ranges[sock_index].first,ranges[sock_index].last);
	if(ranges[sock_index].first>=ranges[sock_index].last){
	  fprintf(stderr,"All ports assigned to %d have been scanned\n",sock_index);
	  return -1;
	}
	if(sock_index<*first||sock_index>*last){
	  fprintf(stderr,"Invalid socket index\n");
	  return -1;
	}
	socklen_t len = sizeof(connections_data[sock_index]);
	int result = connect(sockets[sock_index],(struct sockaddr*)&connections_data[sock_index],len);
        if(result<0){
	   if(errno == EAGAIN || errno == EWOULDBLOCK)return -2;
	}
	return result;
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
    if(sock_index<0 || sock_index>*sockets_needed){
       fprintf(stderr,"Invalid socket index");
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
     ranges[i].first=MAX(*first,i*MAX_PORTS_PER_SOCKET);
     ranges[i].last=MIN((i+1)*MAX_PORTS_PER_SOCKET,*last);
     if(config_socket(i,ranges[i].first)<0){
        fprintf(stderr,"config_socket() number %d|error %d\n",i,errno);
     }
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
      events[i].events=EPOLLOUT;
      if(epoll_ctl(*epoll,EPOLL_CTL_ADD,sockets[i],&events[i])<0){
        fprintf(stderr,"Could not add socket[%d] to epoll\n error %d",i,errno);
      }
   }
   return 0;
}
int start_connection(int index){
   if(sockets[index]<0){
	   sockets[index]=socket(AF_INET,SOCK_STREAM,0);
           config_socket(index,ranges[index].first);
   }
   if(sockets[index]<0){
	   perror("socket still <0");
	   return -1;
   }
   int c = scan_tcp_port(index);
   if(c == 0){
       close(sockets[index]);
       return 1;
   }
   if(c < 0 && errno != EINPROGRESS){
close(sockets[index]);
       return 0;
   }
   else{
       close(sockets[index]);
       return -1;
   }
}
long long get_time(){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec/1000000LL;
}
int run_poll(){
   int left_unscanned = *last-*first+1;
   struct pollfd pfd[*sockets_needed];
   int result[65365];
   int active=0;
   long long start_time[65365]={0};
   long long timeout = 100;
   int maxc = 50;
   long long current_time;

   for(int i=0;i<*sockets_needed;i++){
     pfd[i].fd=sockets[i];
     pfd[i].events = POLLOUT;
   }

   for(int i=0; i<*sockets_needed;i++){
      int c = start_connection(i);
      if(c==1){
        result[ranges[i].first]=1;
	printf("Port %d deschis instant\n",ranges[i].first++);
	left_unscanned--;
      }else if(c==-1){
         pfd[i].fd=sockets[i];
	 pfd[i].events=POLLOUT;
	 pfd[i].revents=0;
	 active++;
      }
      ranges[i].first++;
   }
   while(left_unscanned){
      int n = poll(pfd,active,timeout);
      current_time = get_time();

      if(n<0){
	    if(errno==EINTR)continue;
	    perror("poll");
	    break;
      }

      for(int i=0;i<active;i++){
	 if(pfd[i].fd<0)continue;
	 if(pfd[i].revents==0)continue;
	    
	 int desc = pfd[i].fd;
	 int port = ranges[i].first;
	 int so_err = 0;
	 socklen_t err_size = sizeof(so_err);

         getsockopt(pfd[i].fd,SOL_SOCKET,SO_ERROR,&so_err,&err_size);
         
	 if(so_err==0){
	    result[ranges[i].first]=1;
	    fprintf(stdout,"Port %d deschis\n",ranges[i].first);
	  }
	  else{
	     result[ranges[i].first]=0;
	     perror(strerror(so_err));
	  }
 
          close(desc);
          start_time[ranges[i].first]=0;
	  pfd[i].fd=-1;

	  if(ranges[i].first<ranges[i].last){
	    ranges[i].first++;

	    int rc = start_connection(i);
	    if(rc==1){
               result[ranges[i].first]=1;
               printf("Port %d deschis instant\n",ranges[i].first++);
               left_unscanned--;
            }else if(rc==-1){
                   pfd[i].fd=sockets[i];
                   pfd[i].events=POLLOUT;
                   pfd[i].revents=0;
                   active++;
             }else{
	          pfd[i].fd = -1;
	     }

	    }
            else{
	      if(i<active-1){
	         pfd[i] = pfd[i-1];
		 i--;
	      }
	      active--;
	    }

         }
      }
   //refill free slots
   for(int i=0; i<maxc && left_unscanned;i++){
      if(active>=maxc)break;
      if(i<active)continue;
      if(pfd[i].fd!=-1)continue;
      int rc = start_connection(ranges[i].first);
      left_unscanned--;
      if (rc == 1) {
            result[ranges[i].first] = 1;
            printf("open: %d (instant)\n", ranges[i].first);
            continue;
       } else if (rc == -1) {
           // pfd[i].fd = slots[i].fd;
            pfd[i].events = POLLOUT;
            pfd[i].revents = 0;
            active++;
       }else {
                /* immediate fail */
        }
   }
   //cleanup timed out sockets
   for(int i=0;i<active;i++){
      if(pfd[i].fd<0)continue;
      if(start_time[ranges[i].first]>0 && current_time - start_time[ranges[i].first]){
	 
	 close(pfd[i].fd);
	 start_time[ranges[i].first]=0;
         
	 if(ranges[i].first<ranges[i].last){
            ranges[i].first++;
            int rc = start_connection(i);
              if(rc==1){
                   result[ranges[i].first]=1;
                   printf("Port %d deschis instant\n",ranges[i].first++);
                  left_unscanned--;
              }
	      else if(rc==-1){
                   pfd[i].fd=sockets[i];
                   pfd[i].events=POLLOUT;
                   pfd[i].revents=0;
                   active++;
             }else{
                  pfd[i].fd = -1;
             }
	 }
         else{
              if(i<active-1){
                 pfd[i] = pfd[i-1];
                 i--;
              }
              active--;
            }
      }
   }
   for(int i=*first;i<*last;i++)
      if(result[i])printf("Port %d is opened\n",result[i]);
   return 0;
}
int run_epoll(){
  int left_unscanned = *last-*first+1;
  
//fprintf(stdout,"Trb sa scanam %d porturi\n",left_unscanned);
  int current_socket=0;
  struct epoll_event recieve[150000];
  int fd,rezultat;
  while(left_unscanned){
    
    int n = epoll_wait(*epoll,recieve,MAX_PORTS_PER_SOCKET,-1);
    if(n<0){
       if(errno==EINTR)continue;
       perror("epoll wait");
       break;
    }
    
    for(int i=0;i<n;i++){
       int fd = recieve[i].data.fd;
       uint32_t events = recieve[i].events;

       
       int index=-1;
       for(int j=0;j<*sockets_needed;j++)if(sockets[j]==fd){
	       index=j;
	       break;
       }

       if(index==-1)continue;
       if(sockets[index]<0)continue;

       printf("Scanam pe sockets[%d]\n",current_socket);

       rezultat = scan_tcp_port(index);
       if(rezultat==-2){
            epoll_ctl(*epoll,EPOLL_CTL_DEL,fd,NULL);
	    close(fd);
	    break;
	  }
	  else if(rezultat==-1){
	     printf("Port %d inchis\n",ranges[index].first);
	     ranges[index].first++;
	     left_unscanned--;
	     break;

	  }
	  else if(rezultat==0){
	     printf("Port %d deschis\n",ranges[index].first);
	     left_unscanned--;
	     ranges[index].first++;
	     break;
	  }
       
       struct epoll_event ev;
       ev.data.fd=rezultat;
       ev.events=EPOLLOUT;
       if(epoll_ctl(*epoll,EPOLL_CTL_ADD,rezultat,&ev)<0){
              fprintf(stderr,"Epoll ctl()\n");
	      continue;
       }
       fprintf(stdout,"Mai avem de scanat %d porturi\n",left_unscanned);      
    }
  } 
    return 0;
}
int scan_specific_host(char* host){
        run_poll();	
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
    fprintf(stderr,"Fd limit of %d exceeded",MAX_FD_PER_PROCESS);
    _exit(deallocate_data());
 }

 if(prepare_sockets(*first,*last)<0){
    fprintf(stderr,"prepare_sockets()");
    _exit(deallocate_data());
 }
// config_epoll();
 scan_specific_host(hostname);
// close_epoll();
 close_sockets(*first,*last);
 return deallocate_data();
}
