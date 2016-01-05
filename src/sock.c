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

#include <pthread.h>
#include "sock.h"
#include "destruct.h"

#define UDPTUN_CLI_FILE "data.dat"
static char *serv_file;

static unsigned short calcsum(unsigned short *buffer, int length);
/**
 * \fn int tcp_connect(struct tun_state *st, struct sockaddr *sa, char *filename)
 * \brief Receive an error msg from MSG_ERRQUEUE and print a description 
 *        of it via the debug macro.
 *
 * \param st The program state
 * \param sa The destination sockaddr
 * \param filename The file to write to
 * 
 * \return 0 if an error msg was received, 
 *         a negative value if an error happened
 */ 
static int tcp_connect(struct tun_state *st, struct sockaddr *sa, char *filename);

/**
 * \fn void *serv_worker_thread(void *socket_desc)
 * \brief A server worker that send a file to
 *        one client.
 *
 * \param socket_desc The socket fd 
 * 
 * \return 0 if an error msg was received, 
 *         a negative value if an error happened
 */ 
static void *serv_worker_thread(void *socket_desc);

struct sockaddr_in *get_addr(const char *addr, int port) {
   struct sockaddr_in *ret = malloc(sizeof(struct sockaddr));
   memset(ret, 0, sizeof(struct sockaddr_in));
   ret->sin_family      = AF_INET;
   ret->sin_addr.s_addr = inet_addr(addr);
   ret->sin_port        = htons(port);
   
   return ret;
}

void *serv_thread(void *st) {
   struct tun_state *state = st;
   struct arguments *args = state->args;
   serv_file = state->serv_file;
   tcp_serv(state->private_addr, state->tcp_port, args->if_name, state);
   return 0;
}

int tcp_serv(char *daddr, int dport, char* dev, struct tun_state *state) {

   int s, sin_size;
   struct sockaddr_in sin, sout;

   /* create a TCP socket */
   if ((s=socket(AF_INET, SOCK_STREAM, 0)) < 0) 
     die("socket");
   set_fd(s);
   if (dev && setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev))) 
      die("bind to device");
   
   /* bind to sport */
   memset(&sout, 0, sizeof(sout));
   sout.sin_family = AF_INET;
   inet_pton(AF_INET, daddr, &sout.sin_addr);
   sout.sin_port = htons(dport);

   if (bind(s, (struct sockaddr *)&sout, sizeof(sout)) < 0) 
      die("bind");
   if (listen(s, state->backlog_size) < 0) 
      die("listen");

   debug_print("server ready ...\n");
   int success = 0, ws; // TODO:signal(SIGINT, int_handler) break loop and kill childs
   pthread_t thread_id;
   while(!success) {

      sin_size = sizeof(struct sockaddr_in);
      if ((ws = accept(s, (struct sockaddr *)&sin, &sin_size)) < 0) 
         die("accept");
      debug_print("accepted connection from %s on socket %d.\n", inet_ntoa(sin.sin_addr), ws);

      /* Fork worker thread */
      if (pthread_create(&thread_id, NULL, serv_worker_thread, (void*) &ws) < 0) 
            die("pthread_create");
      set_pthread(thread_id);
   }

   close (s);
   return 0;
}

void *serv_worker_thread(void *socket_desc) {

   char buf[__BUFFSIZE];
   int s = *(int*)socket_desc;

   FILE *fp = fopen(serv_file, "r");
   if(fp == NULL) 
      die("file note found");

   bzero(buf, __BUFFSIZE);
   int bsize = 0, wsize = 0;

   /* Send loop */
   debug_print("sending data ...\n");
   while((bsize = fread(buf, sizeof(char), __BUFFSIZE, fp)) > 0) {
      if((wsize = send(s, buf, bsize, 0)) < 0) {
         debug_print("ERROR: send");
         break;
      }
      if (wsize < bsize) 
         die("file write\n");
      bzero(buf, __BUFFSIZE);
   }

   /* shutdown connection */
   if (shutdown(s, SHUT_RDWR) < 0)
      die("shutdown");

   fclose(fp);close(s);
   debug_print("socket %d successfuly closed.\n", s);

   return 0;
}

int tcp_cli(char *daddr, int dport, char *saddr, int sport, char* dev, char *filename) {
   int s;//TODO remove file argument
   // TODO remove this func
   struct sockaddr_in sin, sout;
   char buf[__BUFFSIZE];
   //create a TCP socket
   if ((s=socket(AF_INET, SOCK_STREAM, 0)) == -1) //IPPROTO_TCP
      die("socket");
   set_fd(s);

   if (dev && setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev))) 
      die("bind to device");
   
   // bind to sport
    memset(&sout, 0, sizeof(sout));
    sout.sin_family = AF_INET;
    sout.sin_port   = htons(sport);
    inet_pton(AF_INET, saddr, &sout.sin_addr);

    if (bind(s, (struct sockaddr *)&sout, sizeof(sout)) < 0) 
        die("bind");
    
   // zero out the structure
   memset(&sin, 0, sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_port   = htons(dport);
   inet_pton(AF_INET, daddr, &sin.sin_addr); 

   debug_print("connecting socket %d\n", s);
   if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) 
        die("connect\n");
   
   /* transfer file */
   FILE *fp = fopen(filename, "w");
   if(fp == NULL) die("fopen");

   bzero(buf, __BUFFSIZE);
   int bsize = 0;
   while(bsize = xrecv(s, buf, __BUFFSIZE)) {
       xfwrite(fp, buf, sizeof(char), bsize);
       bzero(buf, __BUFFSIZE);
   }

   /* shutdown connection */
   if (shutdown(s, SHUT_RDWR) < 0)
      die("shutdown");

   /* wait for fin and send ack */
   if (xrecv(s, buf, __BUFFSIZE) != 0) 
      die("server shutdown");
   fclose(fp);close (s);
   debug_print("socket %d successfuly closed.\n", s);

   /* set file permission */
   mode_t m = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
   if (chmod(filename, m) < 0)
      die("chmod");

   return 0;
}

int tcp_connect(struct tun_state *st, struct sockaddr *sa, char *filename) {

   struct tun_state *state = st;
   struct arguments *args = state->args;
   struct sockaddr_in sout;
   char *dev = args->if_name;
   int s, i, err = 0; 

   /* TCP socket */
   if ((s=socket(AF_INET, SOCK_STREAM, 0)) == -1) //IPPROTO_TCP
      die("socket");
   set_fd(s);

   /* Socket opts */
   int tmp = 1;
   struct timeval snd_timeout = {state->tcp_snd_timeout, 0}; 
   struct timeval rcv_timeout = {state->tcp_rcv_timeout, 0}; 
   if (dev && setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev))) 
      die("bind to device");
   if (setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, (char *)&rcv_timeout,
                sizeof(rcv_timeout)) < 0)
      die("setsockopt failed");
   if (setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, (char *)&snd_timeout,
                sizeof(snd_timeout)) < 0)
      die("setsockopt failed");
    /*if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char *)&tmp,
                sizeof(tmp)) < 0) //TODO maybe useless
        die("setsockopt failed");*/
   
   /* bind socket to local addr */
   memset(&sout, 0, sizeof(sout));
   sout.sin_family = AF_INET;
   sout.sin_port   = htons(state->port);
   inet_pton(AF_INET, state->private_addr, &sout.sin_addr);
   if (bind(s, (struct sockaddr *)&sout, sizeof(sout)) < 0) 
      die("bind");

   /* connect peer */
   struct sockaddr_in sin = *((struct sockaddr_in *)sa);
   debug_print("connecting socket %d\n", s);
   if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
      err=ETIMEDOUT;
      goto err;
   }
   /* transfer file */
   FILE *fp = fopen(state->cli_file, "w");
   if(fp == NULL) die("fopen");

   char buf[__BUFFSIZE];
   bzero(buf, __BUFFSIZE);
   int bsize = 0;
   while(bsize = xrecv(s, buf, __BUFFSIZE)) {
       xfwrite(fp, buf, sizeof(char), bsize);
       bzero(buf, __BUFFSIZE);
   }

   /* shutdown connection */
   if (shutdown(s, SHUT_RDWR) < 0) {
      err=errno;
      goto err;
   }
   /* wait for fin and send ack */
   if (xrecv(s, buf, __BUFFSIZE) != 0) {
      err=errno;
      goto err;
   }

   /* close */
   fclose(fp);close(s);

   /* set file permission */
   mode_t m = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
   if (chmod(filename, m) < 0)
      die("chmod");

succ:
   debug_print("socket %d successfuly closed.\n", s);
   return 0;
err:
   debug_print("socket %d closed on error: %s\n", s, strerror(err));
   close(s);
   return -1;
}

void *cli_thread(void *st) {
   struct tun_state *state = st;
   struct arguments *args = state->args;

   /* Client loop */
   int i; 
   for (i=0; i<state->sa_len; i++) {
      tcp_connect(state, state->cli_private[i]->sa, UDPTUN_CLI_FILE);
   }

   cli_shutdown(0); //TODO per-mode shutdown
   return 0;
}

int udp_sock(int port) {
   int s;
   struct sockaddr_in sin;
   //create a UDP socket
   if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
      die("socket");

   // zero out the structure
   memset(&sin, 0, sizeof(sin));
   sin.sin_family      = AF_INET;
   sin.sin_port        = htons(port);
   sin.sin_addr.s_addr = htonl(INADDR_ANY);

   //bind socket to port
   if( bind(s, (struct sockaddr*)&sin, sizeof(sin) ) == -1)
      die("bind");

   /* enable icmp catching */
   int on = 1;
   if (setsockopt(s, SOL_IP, IP_RECVERR, (char*)&on, sizeof(on))) 
      die("IP_RECVERR");
   
   debug_print("udp socket created on port %d\n", port);
   return s;
}

int raw_tcp_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev) {
   return raw_sock(addr, port, bpf, dev, IPPROTO_TCP);
}

int raw_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev, int proto) {
   int s;
   struct sockaddr_in sin;
   if ((s=socket(PF_INET, SOCK_RAW, proto)) == -1) 
      die("socket");

   int on = 1;
   if (setsockopt(s, 0, IP_HDRINCL, &on, sizeof(on))) 
      die("IP_HDRINCL");

   if (dev && setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev))) 
      die("bind to device");

   //set bpf
   if (bpf && setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, 
                         bpf, sizeof(struct sock_fprog)) < 0 ) 
       die("attach filter");

   memset(&sin, 0, sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_port = htons(port);

   //bind socket to port (PL-specific)
   if(port && bind(s, (struct sockaddr*)&sin, sizeof(sin) ) == -1) 
     die("bind");

   debug_print("raw socket created on %s port %d\n", dev, port);
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
   if (!handle) 
      die( "Couldn't open device %s: %s");
   if (pcap_compile(handle, fp, filter_exp, 0, net) == -1) 
      die("Couldn't parse filter %s: %s\n");

   return (struct sock_fprog *)fp;
}

int xsendto(int fd, struct sockaddr *sa, const void *buf, size_t buflen) {
   int sent = 0;
   if ((sent = sendto(fd,buf,buflen,0,sa,sizeof(struct sockaddr))) < 0) 
       die("sendto");
   return sent;
}

int xrecverr(int fd, void *buf, size_t buflen) {
   struct iovec iov;                      
   struct msghdr msg;                      
   struct cmsghdr *cmsg;                   
   struct sock_extended_err *sock_err;     
   struct icmphdr icmph;  
   struct sockaddr_in remote;

   // init structs
   iov.iov_base       = &icmph;
   iov.iov_len        = sizeof(icmph);
   msg.msg_name       = (void*)&remote;
   msg.msg_namelen    = sizeof(remote);
   msg.msg_iov        = &iov;
   msg.msg_iovlen     = 1;
   msg.msg_flags      = 0;
   msg.msg_control    = buf;
   msg.msg_controllen = buflen;

   // recv msg
   int return_status  = recvmsg(fd, &msg, MSG_ERRQUEUE);
   if (return_status < 0)
      return return_status;

   // parse msg 
   for (cmsg = CMSG_FIRSTHDR(&msg);cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      // ip level and error 
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
         sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg); 
         // icmp msgs
         if (sock_err && sock_err->ee_origin == SO_EE_ORIGIN_ICMP) 
            print_icmp_type(sock_err->ee_type, sock_err->ee_code);
         else debug_print("non-icmp err msg\n");
      } 
   }
   return 0;
}

int xfwerr(int fd, void *buf, size_t buflen, int fd_out, struct tun_state *state) {
   struct iovec iov;                      
   struct msghdr msg;                      
   struct cmsghdr *cmsg;                   
   struct sock_extended_err *sock_err;     
   struct icmphdr icmph;  
   struct sockaddr_in remote;

   // init structs
   iov.iov_base       = &icmph;
   iov.iov_len        = sizeof(icmph);
   msg.msg_name       = (void*)&remote;
   msg.msg_namelen    = sizeof(remote);
   msg.msg_iov        = &iov;
   msg.msg_iovlen     = 1;
   msg.msg_flags      = 0;
   msg.msg_control    = buf;
   msg.msg_controllen = buflen;

   // recv msg
   int return_status  = recvmsg(fd, &msg, MSG_ERRQUEUE), i;
   if (return_status < 0)
      return return_status;

   // parse msg 
   for (cmsg = CMSG_FIRSTHDR(&msg);cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      // ip level and error 
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
         sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
          /* print err type */
         if (sock_err && sock_err->ee_origin == SO_EE_ORIGIN_ICMP) 
            print_icmp_type(sock_err->ee_type, sock_err->ee_code);
         else debug_print("non-icmp err msg\n");

         struct sockaddr *sa = SO_EE_OFFENDER(sock_err);
         debug_print("%s\n", inet_ntoa(((struct sockaddr_in *)sa)->sin_addr));

         /* re-build icmp msg */
	      struct ip_header* ipheader;
	      struct icmp_msg* icmp;
         char *pkt;
         int pkt_len = sizeof(struct ip_header) + sizeof(struct icmp_msg);
	      if ( (pkt = malloc(pkt_len)) == NULL)
		      die("Could not allocate memory for packet\n");
	      ipheader = (struct ip_header*)pkt;
	      icmp = (struct icmp_msg*)(pkt+sizeof(struct ip_header));

         /* fill packet */
	      ipheader->ver 		= 4; 	
	      ipheader->hl		= 5; 	
	      ipheader->tos		= 0;
	      ipheader->totl		= pkt_len;
	      ipheader->id		= 0;
	      ipheader->notused	= 0;	
	      ipheader->ttl		= 255;  
	      ipheader->prot		= 1;	
	      ipheader->csum		= 0;
	      ipheader->saddr 	= ((struct sockaddr_in *)sa)->sin_addr.s_addr;
	      ipheader->daddr   = (unsigned long)inet_addr(state->private_addr);
	      icmp->type		   = sock_err->ee_type;		
	      icmp->code		   = sock_err->ee_code;		
		   icmp->checksum    = 0;
         for (i=0; i<8; i++)          
            icmp->data[i]  = ((unsigned char *) iov.iov_base)[i];
		   icmp->checksum    = calcsum((unsigned short*)icmp, sizeof(struct icmp_msg));
	      ipheader->csum		= calcsum((unsigned short*)ipheader, sizeof(struct ip_header));

         int sent = xwrite(fd_out, pkt, pkt_len);
         free(pkt);
      } 
   }
   return 0;
}

int xrecv(int fd, void *buf, size_t buflen) {
   int recvd = 0;
   if ((recvd = recvfrom(fd, buf, buflen, 0, NULL, 0)) < 0) {
      xrecverr(fd, buf, buflen);
      die("recvd");
   }
   return recvd;
}

int xrecvfrom(int fd, struct sockaddr *sa, unsigned int *salen, void *buf, size_t buflen) {
   int recvd = 0;
   if ((recvd = recvfrom(fd, buf, buflen, 0, sa, salen)) < 0) {
      debug_print("%s\n",strerror(errno));
      return -1;
   }
   return recvd;
}

void die(char *s) {
    perror(s);
    exit(1);
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


/* calcsum - used to calculate IP and ICMP header checksums using
 * one's compliment of the one's compliment sum of 16 bit words of the header
 */
unsigned short calcsum(unsigned short *buffer, int length) {
	unsigned long sum; 	

	// initialize sum to zero and loop until length (in words) is 0 
	for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words 
		sum += *buffer++;	// add 1 word of buffer to sum and proceed to the next 

	// we may have an extra byte 
	if (length==1)
		sum += (char)*buffer;

	sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16 
	sum += (sum >> 16);		     // add carry 
	return ~sum;
}


