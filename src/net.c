/**
 * \file net.c
 * \brief Networking functions to be used 
 *        in cli, serv and peer mode.
 *
 * \author k.edeline
 * \version 0.1
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "sysconfig.h"
#if defined(BSD_OS)
#  include <net/if_tun.h>
#  include <net/if_dl.h> // ifreq
#elif defined(LINUX_OS)
#  include <linux/if.h>
#  include <linux/if_tun.h> 
#  include <linux/errqueue.h>
#endif

#include "net.h"
#include "debug.h"
#include "cli.h"
#include "destruct.h"
#include "thread.h"
#include "tunalloc.h"
#include "udptun.h"

/** 
 * \struct cli_thread_parallel_args
 *	\brief Client thread arguments (see)
 */
struct cli_thread_parallel_args {
   struct tun_state *state;
   struct sockaddr  *sa;
   char *addr;
   char *filename;
   int port;
   int set_maxseg;
};

/**
 * \var char *serv_file
 * \brief The server file location for inter-thread communication.
 */
static char *serv_file;

/**
 * \fn static int tcp_cli(struct tun_state *st, struct sockaddr *sa, char *filename)
 * \brief Receive an error msg from MSG_ERRQUEUE and print a description 
 *        of it via the debug macro.
 *
 * \param st The program state
 * \param sa The destination sockaddr
 * \param addr The address to bind
 * \param port The port to bind
 * \param tun Tunneled client, set MSS accordingly (-28 Bytes)
 * \param filename The file to write to
 * 
 * \return 0 if an error msg was received, 
 *         a negative value if an error happened
 */ 
static int tcp_cli(struct tun_state *st, struct sockaddr *sa, 
                   char *addr, int port, int tun, char* filename);

/**
 * \fn static int tcp_serv(char *addr, int port, struct tun_state *state)
 * \brief Receive an error msg from MSG_ERRQUEUE and print a description 
 *        of it via the debug macro.
 *
 * \param addr The server address
 * \param port The server port
 * \param set_maxseg Set TCP_MAXSEG option to cfg file value
 * \param state The program state
 * 
 * \return 0 if an error msg was received, 
 *         a negative value if an error happened
 */ 
static int tcp_serv(char *addr, int port, struct tun_state *state, int set_maxseg);

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

/**
 * \fn static void *serv_thread_private(void *socket_desc)
 * \brief Run a TCP file server bound on private addr:port
 *
 * \param st The node state (struct tun_state *)
 */
static void *serv_thread_private(void *st);

/**
 * \fn static void *serv_thread_public(void *socket_desc)
 * \brief Run a TCP file server bound on public addr:port
 *
 * \param st The node state (struct tun_state *)
 */
static void *serv_thread_public(void *st);

/**
 * \fn static void cli_thread_parallel(struct tun_state *state, int index)
 * \brief Run the TCP file clients in parallel.
 *
 * \param state The node state 
 * \param index The peer index (cli_private & cli_public)
 */
static void cli_thread_parallel(struct tun_state *state, int index);

/**
 * \fn static void cli_thread_notun(struct tun_state *state, int index)
 * \brief Run the TCP file clients sequentially, NOTUN flow first.
 *
 * \param state The node state 
 * \param index The peer index (cli_private & cli_public)
 */
static void cli_thread_notun(struct tun_state *state,  int index);

/**
 * \fn static void cli_thread_tun(struct tun_state *state, int index)
 * \brief Run the TCP file clients sequentially, TUN flow first.
 *
 * \param state The node state 
 * \param index The peer index (cli_private & cli_public)
 */
static void cli_thread_tun(struct tun_state *state, int index);

/**
 * \fn  void *forked_cli(void *arg)
 * \brief Stub for tcp_cli fork, used in parallel scheduling mode
 *
 * \aram arg A struct cli_thread_parallel_args specified tcp_cli's args.
 */
static void *forked_cli(void *arg);

struct sockaddr_in *get_addr(const char *addr, int port) {
   struct sockaddr_in *ret = calloc(1, sizeof(struct sockaddr));
   ret->sin_family         = AF_INET;
   ret->sin_addr.s_addr    = inet_addr(addr);
   ret->sin_port           = htons(port);

   return ret;
}

void tun(struct tun_state *state, int *fd_tun) {
   struct arguments *args = state->args;
#if defined(LINUX_OS)
   if (args->planetlab)
      state->tun_if = create_tun_pl(state->private_addr, 
                                    state->private_mask, 
                                    fd_tun);
   else
      state->tun_if = create_tun(state->private_addr, 
                                 state->private_mask, 
                                 state->tun_if, fd_tun); 
#else
   state->tun_if = create_tun(state->private_addr, 
                              state->private_mask, 
                              state->tun_if, fd_tun);
#endif
   if (*fd_tun) set_fd(*fd_tun);
}

void *forked_cli(void *arg) {
   struct cli_thread_parallel_args *args = (struct cli_thread_parallel_args*) arg;
   tcp_cli(args->state, args->sa, 
           args->addr, args->port,
           args->set_maxseg, args->filename);
   return 0;
}

void cli_thread_parallel(struct tun_state *state, int index) {
   /* set thread arguments */
   struct cli_thread_parallel_args args_tun = {state, 
                      state->cli_private[index]->sa, 
                      state->private_addr, state->port, 1, 
                      state->cli_file_tun};
   struct cli_thread_parallel_args args_notun = {state, 
                      state->cli_public[index]->sa, 
                      state->public_addr, state->port, 0, 
                      state->cli_file_notun};

   /* launch threads */
   pthread_t tid_tun   = xthread_create(forked_cli, (void*)&args_tun, 0);
   pthread_t tid_notun = xthread_create(forked_cli, (void*)&args_notun, 0);
   
   /* join threads */
   pthread_join(tid_tun, NULL);
   pthread_join(tid_notun, NULL);
}

void cli_thread_tun(struct tun_state *state, int index) {
   /* run tunneled flow */
   tcp_cli(state, state->cli_private[index]->sa,
           state->private_addr, state->port, 1, state->cli_file_tun);
   /* run notun flow */
   tcp_cli(state, state->cli_public[index]->sa, 
           NULL, state->port, 0, state->cli_file_notun);
}

void cli_thread_notun(struct tun_state *state, int index) {
   /* run notun flow */
   tcp_cli(state, state->cli_public[index]->sa, 
           NULL, state->port, 0, state->cli_file_notun);
   /* run tunneled flow */
   tcp_cli(state, state->cli_private[index]->sa, 
           state->private_addr, state->port, 1, state->cli_file_tun);
}

void *cli_thread(void *st) {
   struct tun_state *state = st;
   struct arguments *args = state->args;

   /* initial sleep */
   sleep(state->initial_sleep);

   /* Client loop */
   for (int i=0; i<state->sa_len; i++) {
      switch (args->cli_mode) {
         case PARALLEL_MODE:
            cli_thread_parallel(state, i);
            break;
         case TUN_FIRST_MODE:
            cli_thread_tun(state, i);
            break;
         case NOTUN_FIRST_MODE:
            cli_thread_notun(state, i);
            break;
         default:
            errno=EINVAL;
            die("cli_mode");
      }
   }

   /* Shutdown client, not peer */
   if (args->mode == CLI_MODE)
      cli_shutdown(0);

   return 0;
}

void *serv_thread(void *st) {
   struct tun_state *state = st;
   serv_file = state->serv_file;
   xthread_create(serv_thread_private, st, 1);
   xthread_create(serv_thread_public, st, 1);

   return 0;
}

void *serv_thread_private(void *st) {
   struct tun_state *state = st;
   tcp_serv(state->private_addr, state->private_port, state, 1);
   return 0;
}

void *serv_thread_public(void *st) {
   struct tun_state *state = st;
   tcp_serv(state->public_addr, state->public_port, state, 0);
   return 0;
}

int tcp_serv(char *addr, int port, struct tun_state *state, int set_maxseg) {
   int s;
   unsigned int sin_size;
   struct sockaddr_in sin, sout;

   /* TCP socket */
   if ((s=socket(AF_INET, SOCK_STREAM, 0)) < 0) 
     die("socket");
   set_fd(s);

   /* Set Modified MSS for tunneled TCP */
   if (set_maxseg) {
      int mss = state->max_segment_size;
      if (setsockopt (s, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) < 0)
         die("setsockopt maxseg");
   }

   int on = 1;
   if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
          sizeof(on)) < 0)
      die("setsockopt failed");

   /* bind to sport */
   memset(&sout, 0, sizeof(sout));
   sout.sin_family = AF_INET;
   if (addr)
      inet_pton(AF_INET, addr, &sout.sin_addr);
   else
      sout.sin_addr.s_addr = htonl(INADDR_ANY);
   sout.sin_port = htons(port);

   if (bind(s, (struct sockaddr *)&sout, sizeof(sout)) < 0) {
      debug_print("died binding %s:%d ...\n", addr ? addr : "*", port);
      die("bind tcp server");
   }
   if (listen(s, state->backlog_size) < 0) 
      die("listen");

   /* listen loop */
   debug_print("TCP server listening at %s:%d ...\n", addr ? addr : "*", port);
   int success = 0, ws;
   while(!success) {

      sin_size = sizeof(struct sockaddr_in);
      if ((ws = accept(s, (struct sockaddr *)&sin, &sin_size)) < 0) 
         die("accept");
      debug_print("accepted connection from %s on socket %d.\n", inet_ntoa(sin.sin_addr), ws);

      /* Fork worker thread */
      xthread_create(serv_worker_thread, (void*) &ws, 1);
   }

   close(s);
   return 0;
}

void *serv_worker_thread(void *socket_desc) {
   FILE *fp = fopen(serv_file, "r");
   if(fp == NULL) 
      die("file note found");

   int s = *(int*)socket_desc, err;
   int bsize = 0, wsize = 0;
   char buf[BUFF_SIZE];
   memset(buf, 0, BUFF_SIZE);

   /* Send loop */
   debug_print("sending data ...\n");
   while((bsize = fread(buf, sizeof(char), BUFF_SIZE, fp)) > 0) {
      if((wsize = send(s, buf, bsize, 0)) < 0) {
         debug_print("ERROR: send");
         break;
      }
      if (wsize < bsize) 
         die("file write\n");
      memset(buf, 0, BUFF_SIZE);
   }

   /* shutdown connection */
   if (shutdown(s, SHUT_RDWR) < 0) {
      err=errno;
      goto err;
   }

   fclose(fp);close(s);
   debug_print("socket %d successfuly closed.\n", s);
   return 0;
err:
   fclose(fp);close(s);
   debug_print("socket %d closed on error: %s\n", s, strerror(err));
   return 0;
}

int tcp_cli(struct tun_state *st, struct sockaddr *sa, 
            char *addr, int port, int tun, char* filename) {
   struct tun_state *state = st;
   int s, err = 0; 
   FILE *fp = NULL;
   /* TCP socket */
   if ((s=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) 
      die("socket");
   set_fd(s);

   /* Socket opts */
   struct timeval snd_timeout = {state->tcp_snd_timeout, 0}; 
   struct timeval rcv_timeout = {state->tcp_rcv_timeout, 0}; 
   if (setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout,
                sizeof(rcv_timeout)) < 0)
      die("setsockopt rcvtimeo");
   if (setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &snd_timeout,
                sizeof(snd_timeout)) < 0)
      die("setsockopt sndtimeo");

   /* set tunnel/notunnel specific features */
   if (tun) {
      int mss = state->max_segment_size;
      if (setsockopt (s, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) < 0)
         die("setsockopt maxseg");
   } 
   int on = 1;
   if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
          sizeof(on)) < 0)
      die("setsockopt failed");
   
   /* bind socket to local addr */
   struct sockaddr_in sout;
   memset(&sout, 0, sizeof(sout));
   sout.sin_family = AF_INET;
   sout.sin_port   = htons(port);
   if (addr)
      inet_pton(AF_INET, addr, &sout.sin_addr);
   else
      sout.sin_addr.s_addr = htonl(INADDR_ANY);
   if (bind(s, (struct sockaddr *)&sout, sizeof(sout)) < 0) 
      die("bind tcp cli");
   debug_print("TCP cli bound to %s:%d\n",addr,port);

   /* connect peer */
   struct sockaddr_in sin = *((struct sockaddr_in *)sa);
   debug_print("connecting socket %d\n", s);
   if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {     
      err = (errno == EINPROGRESS) ? ETIMEDOUT : errno;
      goto err;
   }
   /* transfer file */
   fp = fopen(filename, "w");
   if(fp == NULL) die("fopen");

   char buf[BUFF_SIZE];
   memset(buf, 0, BUFF_SIZE);
   int bsize = 0;
   while((bsize = xrecv(s, buf, BUFF_SIZE)) > 0) {
       xfwrite(fp, buf, sizeof(char), bsize);
       memset(buf, 0, BUFF_SIZE);
   } 

   /* shutdown connection */
   if (shutdown(s, SHUT_RDWR) < 0) {
      err=errno;
      goto err;
   }
   /* wait for fin and send ack */
   if (xrecv(s, buf, BUFF_SIZE) != 0) {
      err=errno;
      goto err;
   }

   /* close & set file permission */
   fclose(fp);close(s);
   mode_t m = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
   if (chmod(filename, m) < 0)
      die("chmod");

   debug_print("socket %d successfuly closed.\n", s);
   return 0;
err:
   if (fp) fclose(fp);
   close(s);
   debug_print("socket %d closed on error: %s\n", s, strerror(err));
   return -1;
}

