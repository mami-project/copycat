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

#include "sock.h"

/**
 * \def VSYS_VIFUP_IN 
 * \brief planetlab vsys control file descriptor
 */
#define VSYS_VIFUP_IN "/vsys/vif_up.in"

/**
 * \def VSYS_VIFUP_OUTPUT
 * \brief planetlab vsys control file descriptor
 */
#define VSYS_VIFUP_OUT "/vsys/vif_up.out"

struct sockaddr_in *get_addr(const char *addr, int port) {
   struct sockaddr_in *ret = malloc(sizeof(struct sockaddr));
   memset(ret, 0, sizeof(struct sockaddr_in));
   ret->sin_family      = AF_INET;
   ret->sin_addr.s_addr = inet_addr(addr);
   ret->sin_port        = htons(port);
   
   return ret;
}

int udp_sock(int port) {
   int s;
   struct sockaddr_in sin;
   //create a UDP socket
   if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
   {
     die("socket");
   }

   // zero out the structure
   memset(&sin, 0, sizeof(sin));

   sin.sin_family = AF_INET;
   sin.sin_port = htons(port);
   sin.sin_addr.s_addr = htonl(INADDR_ANY);

   //bind socket to port
   if( bind(s, (struct sockaddr*)&sin, sizeof(sin) ) == -1)
   {
     die("bind");
   }

   return s;
}

int raw_tcp_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev) {
   return raw_sock(addr, port, bpf, dev, IPPROTO_TCP);
}

int raw_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev, int proto) {
   int s;
   struct sockaddr_in sin;
   if ((s=socket(PF_INET, SOCK_RAW, proto)) == -1)
   {
     die("socket");
   }

   int tmp = 1;
   setsockopt(s, 0, IP_HDRINCL, & tmp, sizeof(tmp));

   if (dev && setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev))) {
      die("Cannot bind to device");
   }

   //set bpf
   if (bpf && setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, bpf, sizeof(struct sock_fprog)) < 0 )
   {
       die("Cannot attach filter");
   }

   memset(&sin, 0, sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_port = htons(port);

   //bind socket to port (PL-specific)
   if( bind(s, (struct sockaddr*)&sin, sizeof(sin) ) == -1)
   {
     die("bind");
   }

   return s;
}

struct sock_fprog *gen_bpf(const char *dev, const char *addr, int sport, int dport) {
   pcap_t *handle;		// Session handle 
   char errbuf[PCAP_ERRBUF_SIZE];	// Error string 
   struct bpf_program *fp= malloc(sizeof(struct bpf_program));// The compiled filter expression 

   char filter_exp[64]; // "src port " p " and dst port " p2
   if (sport && dport)
      sprintf(filter_exp, "src port %d and dst port %d", sport, dport);
   else if (sport && !dport)
      sprintf(filter_exp, "src port %d", sport);
   else if (!sport && dport)
      sprintf(filter_exp, "dst port %d", dport);
   bpf_u_int32 net = inet_addr(addr);
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (!handle) {
      die( "Couldn't open device %s: %s");
   }
   if (pcap_compile(handle, fp, filter_exp, 0, net) == -1) {
      die("Couldn't parse filter %s: %s\n");
   }

   return (struct sock_fprog *)fp;
}

int xsendto(int fd, struct sockaddr *sa, const void *buf, size_t buflen) {
   int sent = 0;
   if ( (sent = sendto(fd,buf,buflen,0,sa,sizeof(struct sockaddr)) ) < 0) {
       die("sendto");
   }
   return sent;
}

int xrecv(int fd, void *buf, size_t buflen) {
   int recvd = 0;
   if ((recvd = recvfrom(fd, buf, buflen, 0, NULL, 0)) < 0) {
      die("recvd");
   }
   return recvd;
}

int xrecvfrom(int fd, struct sockaddr *sa, unsigned int *salen, void *buf, size_t buflen) {
   int recvd = 0;
   if ((recvd = recvfrom(fd, buf, buflen, 0, sa, salen)) < 0) {
      die("recvfrom");
   }
   return recvd;
}

char *create_tun(const char *ip, const char *prefix, int nat, int *tun_fds) {
   char *if_name = malloc(IFNAMSIZ);

   FILE *in;
   FILE *out;
   char errbuff[4096];
   memset(errbuff, 0, 4096);

   int tun_fd = tun_alloc(IFF_TUN, if_name);
   if (tun_fds) *tun_fds = tun_fd;

   debug_print("allocated tun device: %s fd=%d\n", if_name, tun_fd);

   in = fopen (VSYS_VIFUP_IN, "a");
   if (!in) {
     debug_print("Failed to open %s\n",VSYS_VIFUP_IN);
     die("fopen VSYS_VIFUP_IN");
   }

   out = fopen (VSYS_VIFUP_OUT, "r");
   if (!out) { 
      debug_print("Failed to open %s\n",VSYS_VIFUP_OUT);
      die("fopen VSYS_VIFUP_OUT");
   }
   
   // send input to process
   if (nat)
      fprintf (in, "%s\n%s\n%s\nsnat=1\n", if_name, ip, prefix);
   else
      fprintf (in, "%s\n%s\n%s\n\n", if_name, ip, prefix);

   // close pipe to indicate end parameter passing and flush the fifo
   fclose (in);

   if (fread((void*)errbuff, 4096, 1, out) && strcmp(errbuff, ""))
      debug_print("%s\n",errbuff);

   fclose (out);
   return if_name;
}

void die(char *s) {
    perror(s);
    exit(1);
}

int xread(int fd, char *buf, int buflen) {
  int nread;
  if((nread=read(fd, buf, buflen)) < 0 ) {
    die("Reading data");
  }
  return nread;
}

int xwrite(int fd, char *buf, int buflen) {
  int nwrite;
  if((nwrite=write(fd, buf, buflen)) < 0 ) {
    die("Writing data");
  }
  return nwrite;
}

