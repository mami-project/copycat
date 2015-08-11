/*
 * sock.c: socket handling
 * 
 *
 * @author k.edeline
 */

#include "sock.h"

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

int raw_tcp_sock(const char *addr, int port, const struct sock_fprog * bpf) {
   return raw_sock(addr, port, bpf, IPPROTO_TCP);
}
//TODO: set non-blocking socket for safe use with select ?
//  fcntl(fd, F_SETFL, O_NONBLOCK))
int raw_sock(const char *addr, int port, const struct sock_fprog * bpf, int proto) {
   int s;
   struct sockaddr_in sin;
   if ((s=socket(PF_INET, SOCK_RAW, proto)) == -1)
   {
     die("socket");
   }

   int tmp = 1;
   setsockopt(s, 0, IP_HDRINCL, & tmp, sizeof(tmp));

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

/*
 *
 * @returns the compiled bpf program: tcpdump -i dev 'src port sport and dst port dport'
 */
struct sock_fprog *gen_bpf(const char *dev, const char *addr, int sport, int dport) {
   pcap_t *handle;		/* Session handle */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   struct bpf_program *fp= malloc(sizeof(struct bpf_program));/* The compiled filter expression */

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

void xsendto(int fd, struct sockaddr_in *addr, const void *buf, size_t buflen) {
   if (sendto(fd,buf,buflen,0,
       (struct sockaddr *)addr,sizeof(struct sockaddr))<0) {
       die("sendto");
   }
}

int xrecv(int fd, void *buf, size_t buflen) {
   int recvd = 0;
   if ( (recvd = recvfrom(fd, buf, buflen, 0, NULL, 0)) < 0) {
      die("recvd");
   }
   return recvd;
}

int xrecvfrom(int fd, void *buf, size_t buflen, struct sockaddr *sa, unsigned int *salen) {
   int recvd = 0;
   if ( (recvd = recvfrom(fd, buf, buflen, 0, sa, salen)) < 0) {
      die("recvfrom");
   }
   return recvd;
}

char *create_tun(const char *ip, const char *prefix, int nat) {
   char *if_name = malloc(IFNAMSIZ);

   FILE *in;
   FILE *out;
   char errbuff[4096];
   memset(errbuff, 0, 4096);

   int tun_fd = tun_alloc(IFF_TUN, if_name);
#ifdef __DEBUG
   fprintf(stderr,"allocated tun device: %s fd=%d\n", if_name, tun_fd);
#endif

   in = fopen (VSYS_VIFUP_IN, "a");
   if (!in) 
     fprintf(stderr,"Failed to open %s\n",VSYS_VIFUP_IN);
   

   out = fopen (VSYS_VIFUP_OUT, "r");
   if (!out) 
      fprintf(stderr,"Failed to open %s\n",VSYS_VIFUP_OUT);
   
   // send input to process
   if (nat)
      fprintf (in, "%s\n%s\n%s\nsnat=1\n", if_name, ip, prefix);
   else
      fprintf (in, "%s\n%s\n%s\n\n", if_name, ip, prefix);

   // close pipe to indicate end parameter passing and flush the fifo
   fclose (in);

   if (fread((void*)errbuff, 4096, 1, out) && strcmp(errbuff, ""))
      fprintf(stderr,"%s\n",errbuff);

   fclose (out);
   return if_name;
}
