/**
 * \file sock.c
 * \brief Socket handling.
 *
 *    This contains system calls wrappers, socket and BPF creation 
 *    functions, tun interface creation functions, network utility 
 *    functions and die().
 *    Note that raw socket and tun interface related functions are 
 *    Planetlab-specific.
 *
 * \author k.edeline
 * \version 0.1
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include "sysconfig.h"
#if defined(BSD_OS)
#  include <net/if_tun.h>
#  include <net/if_dl.h>
#elif defined(LINUX_OS)
#  include <linux/if.h>
#  include <linux/if_tun.h>
#  include <linux/errqueue.h>
#endif

#include "sock.h"
#include "debug.h"
#include "icmp.h"
#include "net.h"
#include "xpcap.h"
#include "destruct.h"

/**
 * \fn static build_sel(fd_set *input_set, int *fds_raw, int len, int *max_fd_raw)
 *
 * \brief build a fd_set structure to be used with select() or similar.
 *
 * \param input_set modified on return to the fd_set.
 * \param fds_raw The fd to set.
 * \param len The number of fd.
 * \param max_fd_raw modified on return to indicate the max fd value.
 */ 
static void build_sel(fd_set *input_set, int *fds_raw, int len, int *max_fd_raw);

char *addr_to_itf(char *addr) {
   struct ifaddrs *addrs, *iap;
   struct sockaddr_in *sa;
   char buf[32];

   getifaddrs(&addrs);
   for (iap = addrs; iap != NULL; iap = iap->ifa_next) {
      if (iap->ifa_addr && (iap->ifa_flags & IFF_UP) && iap->ifa_addr->sa_family == AF_INET) {
         sa = (struct sockaddr_in *)(iap->ifa_addr);
         inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), buf, sizeof(buf));
         if (!strcmp(addr, buf)) 
            return strdup(iap->ifa_name);
      }
   }
   freeifaddrs(addrs);
   return NULL;
}

int udp_sock(int port, uint8_t register_gc, char *addr) { //TODO switch types
   int s;
   /* UDP socket */
   if ((s=socket(AF_INET, SOCK_DGRAM, 0)) == -1)
      die("socket");
   if (register_gc)
      set_fd(s);

   /* sockaddr */
   struct sockaddr_in sin;
   memset(&sin, 0, sizeof(sin));
   sin.sin_family      = AF_INET;
   sin.sin_port        = htons(port);
   //sin.sin_addr.s_addr = htonl(INADDR_ANY);
   inet_pton(AF_INET, addr, &sin.sin_addr);

   /* bind to port */
   if( bind(s, (struct sockaddr*)&sin, sizeof(sin) ) == -1)
      die("bind udp socket");

#if defined(IP_RECVERR)
   /* enable icmp catching */
   int on = 1;
   if (setsockopt(s, SOL_IP, IP_RECVERR, (char*)&on, sizeof(on))) 
      die("IP_RECVERR");
#endif
   debug_print("udp socket created on port %d\n", port);
   return s;
}
// TODO add const

#if defined(LINUX_OS)
int raw_tcp_sock(int port, const struct sock_fprog * bpf, const char *dev) {
   return raw_sock(port, bpf, dev, IPPROTO_TCP);
}

int raw_sock(int port, const struct sock_fprog * bpf, const char *dev, int proto) {
   int s;
   struct sockaddr_in sin;
   if ((s=socket(PF_INET, SOCK_RAW, proto)) == -1) 
      die("socket");

   int on = 1;
   if (setsockopt(s, 0, IP_HDRINCL, &on, sizeof(on))) 
      die("IP_HDRINCL");

#if defined(SO_BINDTODEVICE)
   if (dev && setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev))) 
      die("bind to device");
#endif
#if defined(SO_ATTACH_FILTER)
   /* set bpf */
   if (bpf && setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, 
                         bpf, sizeof(struct sock_fprog)) < 0 ) 
       die("attach filter");
#endif
   memset(&sin, 0, sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_port = htons(port);

   /* bind socket to port (PL-specific) */
   if(port && bind(s, (struct sockaddr*)&sin, sizeof(sin) ) == -1) 
     die("bind");

   debug_print("raw socket created on %s port %d\n", dev, port);
   return s;
}
#endif

int xselect(fd_set *input_set, int fd_max, struct timeval *tv, int timeout) {
   int sel;
   if (timeout != -1) {
      tv->tv_sec  = timeout;
      tv->tv_usec = 0;
      sel = select(fd_max+1, input_set, NULL, NULL, tv);
   } else {
      sel = select(fd_max+1, input_set, NULL, NULL, NULL);
   }
   if (sel < 0) die("select");
   return sel;
}

int xsendto(int fd, struct sockaddr *sa, const void *buf, size_t buflen) {
   int sent = 0;
   if ((sent = sendto(fd,buf,buflen,0,sa,sizeof(struct sockaddr))) < 0) 
       die("sendto");
   return sent;
}

int xrecverr(int fd, void *buf, size_t buflen, int fd_out, struct tun_state *state) {
#if defined(IP_RECVERR)
   struct iovec iov;                      
   struct msghdr msg;                      
   struct cmsghdr *cmsg;                   
   struct sock_extended_err *sock_err;     
   struct icmphdr icmph;  
   struct sockaddr_in remote;

   /* init structs */
   iov.iov_base       = &icmph;
   iov.iov_len        = sizeof(icmph);
   msg.msg_name       = (void*)&remote;
   msg.msg_namelen    = sizeof(remote);
   msg.msg_iov        = &iov;
   msg.msg_iovlen     = 1;
   msg.msg_flags      = 0;
   msg.msg_control    = buf;
   msg.msg_controllen = buflen;

   /* recv msg */
   if (recvmsg(fd, &msg, MSG_ERRQUEUE) < 0)
      die("recvmsg");

   /* parse msg */
   for (cmsg = CMSG_FIRSTHDR(&msg);cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      /* ip level and error */
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
         sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg); 
         /* icmp msgs */
         if (sock_err && sock_err->ee_origin == SO_EE_ORIGIN_ICMP) 
            print_icmp_type(sock_err->ee_type, sock_err->ee_code);
         else debug_print("non-icmp err msg\n");

         if (state) {
            /* re-build icmp msg and forward it */
            int pkt_len; 
            char *pkt = forge_icmp(&pkt_len, sock_err, &iov, state);
            xwrite(fd_out, pkt, pkt_len);
            free(pkt); 
         }
      } 
   }
#else
   debug_print("recvd icmp\n");
#endif
   return 0;
}

int xrecv(int fd, void *buf, size_t buflen) {
   int recvd = 0;
   if ((recvd = recvfrom(fd, buf, buflen, 0, NULL, 0)) < 0) {
      debug_print("%s\n",strerror(errno));
      return -1;
   }
   return recvd;
}

int xrecvfrom(int fd, struct sockaddr *sa, 
              unsigned int *salen, 
              void *buf, size_t buflen) {
   int recvd = 0;
   if ((recvd = recvfrom(fd, buf, buflen, 0, sa, salen)) < 0) {
      debug_print("%s\n",strerror(errno));
      return -1;
   }
   return recvd;
}

int xread(int fd, char *buf, int buflen) {
   int nread;
   if((nread=read(fd, buf, buflen)) < 0) 
      die("read");
   return nread;
}

int xwrite(int fd, char *buf, int buflen) {
   int nwrite;
   if((nwrite=write(fd, buf, buflen)) < 0) 
      die("write");
   return nwrite;
}

int xfwrite(FILE *fp, char *buf, int size, int nmemb) {
   int wsize = fwrite(buf, size, nmemb, fp); 
   if(wsize < nmemb) 
      die("fwrite");
   return wsize;
}

void die(char *s) {
    perror(s);
    exit(1);
}

void build_sel(fd_set *input_set, int *fds_raw, int len, int *max_fd_raw) {
   int i = 0, max_fd = 0, fd = 0;
   FD_ZERO(input_set);
   for (;i<len;i++) {
      fd = fds_raw[i];
      if (fd) {
       FD_SET(fd, input_set);
       max_fd = max(fd,max_fd);
      } else break;
   }

   *max_fd_raw = max_fd;
}

