#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zmq.h>
static volatile sig_atomic_t stopping;
static uint64_t packets, bytes, messages, payload_bytes, bad, sockdrops;
static int udpfd=-1;
static const char *dest;
static double now(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void stop(int s) {(void)s;stopping=1;}
/* SO_RXQ_OVFL ancillary data is only attached to a later delivered datagram.
 * Read the socket's actual drop count before close, including tail drops. */
static void final_udp_drops(void) {
 if(udpfd<0)return;struct stat st;if(fstat(udpfd,&st))return;
 FILE*f=fopen("/proc/net/udp","r");if(!f)return;char line[2048];
 while(fgets(line,sizeof(line),f)){char*save=NULL;char*t=strtok_r(line," \t\n",&save);unsigned i=0;uint64_t inode=0,last=0;
  while(t){if(i==9)inode=strtoull(t,NULL,10);last=strtoull(t,NULL,10);i++;t=strtok_r(NULL," \t\n",&save);}
  if(inode==(uint64_t)st.st_ino&&i>=13){if(last>sockdrops)sockdrops=last;break;}
 }fclose(f);
}
static void status(void) {
 char tmp[512];snprintf(tmp,sizeof(tmp),"%s.tmp",dest);FILE*f=fopen(tmp,"w");if(!f)return;
 fprintf(f,"{\"time\":%.9f,\"packets\":%lu,\"inner_bytes\":%lu,\"messages\":%lu,\"payload_bytes\":%lu,\"bad\":%lu,\"socket_drops\":%lu}\n",now(),packets,bytes,messages,payload_bytes,bad,sockdrops);fclose(f);rename(tmp,dest);
}
static unsigned be16(const unsigned char*p){return p[0]*256+p[1];}
static unsigned be32(const unsigned char*p){return p[0]*16777216u+p[1]*65536u+p[2]*256u+p[3];}
static int frame(const unsigned char*p,size_t n,int mpls) {
 if(n!=(mpls?68:64)||p[0]!=0x1a||p[1]!=0xca||p[2]!=0x0a||p[3]!=0x26||p[4]!=0xa8||p[5]!=0x8c)return 0;
 if(be16(p+12)!=(mpls?0x8847:0x0800))return 0;
 const unsigned char*ip=p+14+(mpls?4:0);
 return ip[0]==0x45&&ip[9]==17&&be32(ip+12)==0x0a02000c&&be32(ip+16)==0x0a02000b&&be16(ip+22)==49001;
}
int main(int argc,char**argv) {
 if(argc!=4)return 2;dest=argv[3];signal(SIGTERM,stop);signal(SIGINT,stop);
 int iszmq=!strcmp(argv[1],"zmq"),isgre=!strcmp(argv[1],"gre");double pub=now();status();
 if(iszmq){
  void*ctx=zmq_ctx_new();void*s=zmq_socket(ctx,ZMQ_PULL);int timeout=100,hwm=1000,linger=0;
  zmq_setsockopt(s,ZMQ_RCVTIMEO,&timeout,sizeof(timeout));zmq_setsockopt(s,ZMQ_RCVHWM,&hwm,sizeof(hwm));zmq_setsockopt(s,ZMQ_LINGER,&linger,sizeof(linger));
  char endpoint[100];snprintf(endpoint,sizeof(endpoint),"tcp://10.0.0.10:%s",argv[2]);if(zmq_bind(s,endpoint)){perror("bind zmq");return 3;}
  puts("RECEIVER_READY zmq PULL");fflush(stdout);
  while(!stopping){zmq_msg_t m;zmq_msg_init(&m);int rc=zmq_msg_recv(&m,s,0);
   if(rc>=0){size_t n=zmq_msg_size(&m);const unsigned char*p=zmq_msg_data(&m);messages++;payload_bytes+=n;
    size_t off=24;unsigned cnt=n>=24?be16(p+2):0,valid=0;
    if(n<24||be16(p)!=2)bad++;
    else {for(unsigned j=0;j<cnt;j++){if(off+18>n){bad++;break;}unsigned len=be16(p+off);unsigned cap=be32(p+off+10),wire=be32(p+off+14);off+=18;
      if(off+len>n){bad++;break;}if(cap!=len||wire!=68||!frame(p+off,len,1))bad++;else{packets++;bytes+=64;valid++;}off+=len;}
     if(off!=n||valid!=cnt)bad++;}
   }else if(errno!=EAGAIN&&errno!=EINTR){perror("zmq recv");bad++;}
   zmq_msg_close(&m);if(now()-pub>.1){status();pub=now();}
  }zmq_close(s);zmq_ctx_term(ctx);
 }else{
  int s=socket(AF_INET,isgre?SOCK_RAW:SOCK_DGRAM,isgre?IPPROTO_GRE:0);if(s<0){perror("socket");return 4;}
  if(!isgre)udpfd=s;
  int buf=64*1024*1024,one=1;setsockopt(s,SOL_SOCKET,SO_RCVBUF,&buf,sizeof(buf));setsockopt(s,SOL_SOCKET,SO_RXQ_OVFL,&one,sizeof(one));
  struct timeval timeout={.tv_usec=100000};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
  struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(atoi(argv[2]))};inet_pton(AF_INET,"10.0.0.10",&a.sin_addr);
  if(bind(s,(void*)&a,sizeof(a))){perror("bind");return 5;}
  enum{B=128};struct mmsghdr mm[B];struct iovec io[B];unsigned char data[B][256],ctrl[B][64];memset(mm,0,sizeof(mm));
  for(int i=0;i<B;i++){io[i]=(struct iovec){data[i],sizeof(data[i])};mm[i].msg_hdr.msg_iov=&io[i];mm[i].msg_hdr.msg_iovlen=1;mm[i].msg_hdr.msg_control=ctrl[i];mm[i].msg_hdr.msg_controllen=64;}
  puts("RECEIVER_READY datagram recvmmsg");fflush(stdout);
  while(!stopping){for(int i=0;i<B;i++){mm[i].msg_hdr.msg_controllen=64;mm[i].msg_hdr.msg_flags=0;}int got=recvmmsg(s,mm,B,MSG_WAITFORONE,NULL);
   for(int i=0;i<got;i++){unsigned char*p=data[i];size_t n=mm[i].msg_len;messages++;payload_bytes+=n;
    for(struct cmsghdr*c=CMSG_FIRSTHDR(&mm[i].msg_hdr);c;c=CMSG_NXTHDR(&mm[i].msg_hdr,c))if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SO_RXQ_OVFL){uint32_t v;memcpy(&v,CMSG_DATA(c),4);sockdrops=v;}
    size_t off=8;if(isgre){if(n<20){bad++;continue;}off=(p[0]&15)*4;if(n<off+8||be16(p+off)!=0x2000||be16(p+off+2)!=0x6558){bad++;continue;}off+=8;}
    else if(n<8||p[0]!=8){bad++;continue;}
    if(n>=off&&frame(p+off,n-off,0)){packets++;bytes+=64;}else bad++;
   }if(now()-pub>.1){status();pub=now();}
  }final_udp_drops();close(s);udpfd=-1;
 }status();return bad?6:0;
}










