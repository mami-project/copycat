/**
 * \file net.c
 * \brief Networking functions to be used 
 *        in cli, serv and peer mode.
 *
 * \author k.edeline
 * \version 0.1
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/errqueue.h>
#include <sys/socket.h>

#include "net.h"
#include "debug.h"
#include "cli.h"
#include "destruct.h"
#include "thread.h"
#include "tunalloc.h"

static char *serv_file;

/**
 * \fn static int tcp_cli(struct tun_state *st, struct sockaddr *sa, char *filename)
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
static int tcp_cli(struct tun_state *st, struct sockaddr *sa);

/**
 * \fn static int tcp_serv(char *addr, int port, char* dev, struct tun_state *state)
 * \brief Receive an error msg from MSG_ERRQUEUE and print a description 
 *        of it via the debug macro.
 *
 * \param addr The server address
 * \param port The server port
 * \param dev  The device to bind to
 * \param state The program state
 * 
 * \return 0 if an error msg was received, 
 *         a negative value if an error happened
 */ 
static int tcp_serv(char *addr, int port, char* dev, struct tun_state *state);

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
   struct sockaddr_in *ret = calloc(1, sizeof(struct sockaddr));
   ret->sin_family         = AF_INET;
   ret->sin_addr.s_addr    = inet_addr(addr);
   ret->sin_port           = htons(port);

   return ret;
}

void tun(struct tun_state *state, int *fd_tun) {
   struct arguments *args = state->args;
   if (args->planetlab)
      args->if_name  = create_tun_pl(state->private_addr, state->private_mask, fd_tun);
   else if (args->freebsd)
      args->if_name  = create_tun_pl(state->private_addr, state->private_mask, fd_tun);
   else
      args->if_name  = create_tun(state->private_addr, state->private_mask, NULL, fd_tun); 
}

void *cli_thread(void *st) {
   int i; 
   struct tun_state *state = st;
   struct arguments *args = state->args;

   /* Client loop */
   for (i=0; i<state->sa_len; i++) 
      tcp_cli(state, state->cli_private[i]->sa);

   /* Shutdown client, not peer */
   cli_shutdown(0);
   return 0;
}

void *serv_thread(void *st) {
   struct tun_state *state = st;
   struct arguments *args = state->args;
   serv_file = state->serv_file;
   tcp_serv(state->private_addr, state->tcp_port, args->if_name, state);
   return 0;
}

int tcp_serv(char *daddr, int dport, char* dev, struct tun_state *state) {

   int s, sin_size, tmp;
   struct sockaddr_in sin, sout;

   /* TCP socket */
   if ((s=socket(AF_INET, SOCK_STREAM, 0)) < 0) 
     die("socket");
   set_fd(s);
   if (dev && setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev))) 
      die("bind to device");
   tmp = state->max_segment_size;
   if (setsockopt (s, IPPROTO_TCP, TCP_MAXSEG, &tmp, sizeof(tmp)) < 0)
      die("setsockopt maxseg");
   
   /* bind to sport */
   memset(&sout, 0, sizeof(sout));
   sout.sin_family = AF_INET;
   inet_pton(AF_INET, daddr, &sout.sin_addr);
   sout.sin_port = htons(dport);

   if (bind(s, (struct sockaddr *)&sout, sizeof(sout)) < 0) 
      die("bind");
   if (listen(s, state->backlog_size) < 0) 
      die("listen");

   /* listen loop */
   debug_print("server ready ...\n");
   int success = 0, ws;
   pthread_t thread_id;
   while(!success) {

      sin_size = sizeof(struct sockaddr_in);
      if ((ws = accept(s, (struct sockaddr *)&sin, &sin_size)) < 0) 
         die("accept");
      debug_print("accepted connection from %s on socket %d.\n", inet_ntoa(sin.sin_addr), ws);

      /* Fork worker thread */
      xthread_create(serv_worker_thread, (void*) &ws);
   }

   close(s);
   return 0;
}

void *serv_worker_thread(void *socket_desc) {

   char buf[__BUFFSIZE];
   int s = *(int*)socket_desc;

   FILE *fp = fopen(serv_file, "r");
   if(fp == NULL) 
      die("file note found");

   memset(buf, 0, __BUFFSIZE);
   int bsize = 0, wsize = 0;

   /* Send loop */
   debug_print("sending data ...\n");
   while((bsize = fread(buf, sizeof(char), __BUFFSIZE, fp)) > 0) {
      if((wsize = send(s, buf, bsize, 0)) < 0) { // TODO change buffer size for mss in old kernels without maxseg
         debug_print("ERROR: send");
         break;
      }
      if (wsize < bsize) 
         die("file write\n");
      memset(buf, 0, __BUFFSIZE);
   }

   /* shutdown connection */
   if (shutdown(s, SHUT_RDWR) < 0)
      die("shutdown");

   fclose(fp);close(s);
   debug_print("socket %d successfuly closed.\n", s);

   return 0;
}

int tcp_cli(struct tun_state *st, struct sockaddr *sa) {

   struct tun_state *state = st;
   struct arguments *args = state->args;
   struct sockaddr_in sout;
   char *dev = args->if_name;
   int s, i, err = 0, tmp; 

   /* TCP socket */
   if ((s=socket(AF_INET, SOCK_STREAM, 0)) == -1) 
      die("socket");
   set_fd(s);

   /* Socket opts */
   struct timeval snd_timeout = {state->tcp_snd_timeout, 0}; 
   struct timeval rcv_timeout = {state->tcp_rcv_timeout, 0}; 
   if (dev && setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev))) 
      die("bind to device");
   if (setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout,
                sizeof(rcv_timeout)) < 0)
      die("setsockopt rcvtimeo");
   if (setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &snd_timeout,
                sizeof(snd_timeout)) < 0)
      die("setsockopt sndtimeo");

   tmp = state->max_segment_size;
   if (setsockopt (s, IPPROTO_TCP, TCP_MAXSEG, &tmp, sizeof(tmp)) < 0)
      die("setsockopt maxseg");
   
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
   memset(buf, 0, __BUFFSIZE);
   int bsize = 0;
   while(bsize = xrecv(s, buf, __BUFFSIZE)) {
       xfwrite(fp, buf, sizeof(char), bsize);
       memset(buf, 0, __BUFFSIZE);
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
   if (chmod(state->cli_file, m) < 0)
      die("chmod");

succ:
   debug_print("socket %d successfuly closed.\n", s);
   return 0;
err:
   debug_print("socket %d closed on error: %s\n", s, strerror(err));
   close(s);
   return -1;
}

