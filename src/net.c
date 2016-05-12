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
 * \fn static int tcp_cli4(struct tun_state *st, struct sockaddr *sa, char *filename)
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
            char *addr, int port, int tun, char* filename, sa_family_t sfam);

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
static int tcp_serv(char *addr, int port, struct tun_state *state, 
                     int set_maxseg, sa_family_t sfam);

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
 * \fn static void *serv_thread_private4(void *socket_desc)
 * \brief Run a TCP file server bound on private addr:port
 *
 * \param st The node state (struct tun_state *)
 */
static void *serv_thread_private4(void *st);
static void *serv_thread_private6(void *st);

/**
 * \fn static void *serv_thread_public4(void *socket_desc)
 * \brief Run a TCP file server bound on public addr:port
 *
 * \param st The node state (struct tun_state *)
 */
static void *serv_thread_public4(void *st);
static void *serv_thread_public6(void *st);

/**
 * \fn static void cli_thread_parallel4(struct tun_state *state, int index)
 * \brief Run the TCP file clients in parallel.
 *
 * \param state The node state 
 * \param index The peer index (cli_private & cli_public)
 */
static void cli_thread_parallel4(struct tun_state *state, int index);
static void cli_thread_parallel6(struct tun_state *state, int index);
static void cli_thread_parallel46(struct tun_state *state, int index);

/**cli_thread_notun4
 * \fn static void cli_thread_notun4(struct tun_state *state, int index)
 * \brief Run the TCP file clients sequentially, NOTUN flow first.
 *
 * \param state The node state 
 * \param index The peer index (cli_private & cli_public)
 */
static void cli_thread_notun4(struct tun_state *state,  int index);
static void cli_thread_notun6(struct tun_state *state,  int index);

/**
 * \fn static void cli_thread_tun4(struct tun_state *state, int index)
 * \brief Run the TCP file clients sequentially, TUN flow first.
 *
 * \param state The node state 
 * \param index The peer index (cli_private & cli_public)
 */
static void cli_thread_tun4(struct tun_state *state, int index);
static void cli_thread_tun6(struct tun_state *state, int index);

/**
 * \fn  void *forked_cli4(void *arg)
 * \brief Stub for tcp_cli fork, used in parallel scheduling mode
 *
 * \aram arg A struct cli_thread_parallel_args specified tcp_cli's args.
 */
static void *forked_cli4(void *arg);
static void *forked_cli6(void *arg);

void tun(struct tun_state *state, int *fd_tun) {
   struct arguments *args = state->args;
   char *new_if = NULL;
#if defined(LINUX_OS)
   if (args->planetlab)
      new_if = create_tun_pl(state->private_addr4, 
                                    state->private_mask4, 
                                    fd_tun);
   else 
#endif
   if (args->ipv6 || args->dual_stack)
      new_if = create_tun46(state->private_addr4, state->private_mask4, 
                            state->private_addr6, state->private_mask6, 
                            state->tun_if, fd_tun); 
   else
      new_if = create_tun4(state->private_addr4, 
                           state->private_mask4, 
                           state->tun_if, fd_tun); 

   /* swap wished name with actual name */
   if (new_if) {
      if (state->tun_if)
         free(state->tun_if);
      state->tun_if = new_if;
   }
   if (*fd_tun) set_fd(*fd_tun);
}

void *forked_cli4(void *arg) {
   struct cli_thread_parallel_args *args = (struct cli_thread_parallel_args*) arg;
   tcp_cli(args->state, args->sa, 
           args->addr, args->port,
           args->set_maxseg, args->filename, AF_INET);
   return 0;
}

void *forked_cli6(void *arg) {
   struct cli_thread_parallel_args *args = (struct cli_thread_parallel_args*) arg;
   tcp_cli(args->state, args->sa, 
           args->addr, args->port,
           args->set_maxseg, args->filename, AF_INET6);
   return 0;
}

void cli_thread_parallel4(struct tun_state *state, int index) {
   /* set thread arguments */

   struct cli_thread_parallel_args args_tun = {state, 
                         state->cli_private[index]->sa4, 
                         state->private_addr4, 
                         state->cli_file_tun4,
                         state->port, state->max_segment_size
                      };
   struct cli_thread_parallel_args args_notun = {state, 
                         state->cli_public[index]->sa4, 
                         state->public_addr4, 
                         state->cli_file_notun4,
                         state->port, 0
                      };

   /* launch threads */
   pthread_t tid_tun   = xthread_create(forked_cli4, (void*)&args_tun, 0);
   pthread_t tid_notun = xthread_create(forked_cli4, (void*)&args_notun, 0);
   
   /* join threads */
   pthread_join(tid_tun, NULL);
   pthread_join(tid_notun, NULL);
}

void cli_thread_parallel6(struct tun_state *state, int index) {
   /* set thread arguments */

   struct cli_thread_parallel_args args_tun = {state, 
                         state->cli_private[index]->sa6, 
                         state->private_addr6, 
                         state->cli_file_tun6,
                         state->port, state->max_segment_size
                      };
   struct cli_thread_parallel_args args_notun = {state, 
                         state->cli_public[index]->sa6, 
                         state->public_addr6, 
                         state->cli_file_notun6,
                         state->port, 0
                      };

   /* launch threads */
   pthread_t tid_tun   = xthread_create(forked_cli6, (void*)&args_tun, 0);
   pthread_t tid_notun = xthread_create(forked_cli6, (void*)&args_notun, 0);
   
   /* join threads */
   pthread_join(tid_tun, NULL);
   pthread_join(tid_notun, NULL);
}

void cli_thread_parallel46(struct tun_state *state, int index) {
   struct cli_thread_parallel_args args_tun4 = {state, 
                         state->cli_private[index]->sa4, 
                         state->private_addr4, 
                         state->cli_file_tun4,
                         state->port, state->max_segment_size,
                      };
   struct cli_thread_parallel_args args_notun4 = {state, 
                         state->cli_public[index]->sa4, 
                         state->public_addr4, 
                         state->cli_file_notun4,
                         state->port, 0
                      };
   struct cli_thread_parallel_args args_tun6 = {state, 
                         state->cli_private[index]->sa6, 
                         state->private_addr6, 
                         state->cli_file_tun6,
                         state->port, state->max_segment_size
                      };
   struct cli_thread_parallel_args args_notun6 = {state, 
                         state->cli_public[index]->sa6, 
                         state->public_addr6, 
                         state->cli_file_notun6,
                         state->port, 0
                      };

   /* launch IPv4 cli */
   pthread_t tid4 = xthread_create(forked_cli4, (void*)&args_notun4, 0);
   pthread_t tid6 = xthread_create(forked_cli6, (void*)&args_notun6, 0);
   
   /* join threads */
   pthread_join(tid4, NULL);
   pthread_join(tid6, NULL);

   /* launch IPv6 cli */
   tid4 = xthread_create(forked_cli4, (void*)&args_tun4, 0);
   tid6 = xthread_create(forked_cli6, (void*)&args_tun6, 0);
   
   /* join threads */
   pthread_join(tid4, NULL);
   pthread_join(tid6, NULL);
}

void cli_thread_tun4(struct tun_state *state, int index) {
   /* run tunneled flow */
   tcp_cli(state, state->cli_private[index]->sa4,
           state->private_addr4, state->port, state->max_segment_size, 
            state->cli_file_tun4, AF_INET);
   /* run notun flow */
   tcp_cli(state, state->cli_public[index]->sa4, 
           NULL, state->port, 0, state->cli_file_notun4, AF_INET);
}

void cli_thread_tun6(struct tun_state *state, int index) {
   /* run tunneled flow */
   tcp_cli(state, state->cli_private[index]->sa6,
           state->private_addr6, state->port, state->max_segment_size, 
           state->cli_file_tun6, AF_INET6);
   /* run notun flow */
   tcp_cli(state, state->cli_public[index]->sa6, 
           NULL, state->port, 0, state->cli_file_notun6, AF_INET6);
}

void cli_thread_notun4(struct tun_state *state, int index) {
   /* run notun flow */
   tcp_cli(state, state->cli_public[index]->sa4, 
           NULL, state->port, 0, state->cli_file_notun4, AF_INET);
   /* run tunneled flow */
   tcp_cli(state, state->cli_private[index]->sa4, 
           state->private_addr4, state->port, state->max_segment_size, 
           state->cli_file_tun4, AF_INET);
}

void cli_thread_notun6(struct tun_state *state, int index) {
   /* run notun flow */
   tcp_cli(state, state->cli_public[index]->sa6, 
           NULL, state->port, 0, state->cli_file_notun6, AF_INET6);
   /* run tunneled flow */
   tcp_cli(state, state->cli_private[index]->sa6, 
           state->private_addr6, state->port, state->max_segment_size, 
           state->cli_file_tun6, AF_INET6);
}

void *cli_thread(void *st) {
   struct tun_state *state = st;
   struct arguments *args = state->args;

   /* pick functions */
   void (*cli_thread)(struct tun_state*, int);
   switch (args->cli_mode) {
      case PARALLEL_MODE:
         if (state->dual_stack)
            cli_thread = &cli_thread_parallel46;
         else if (state->ipv6)
            cli_thread = &cli_thread_parallel6;
         else
            cli_thread = &cli_thread_parallel4;
         break;
      case TUN_FIRST_MODE:
         if (state->dual_stack)
            cli_thread = &cli_thread_parallel46;
         else if (state->ipv6)
            cli_thread = &cli_thread_tun6;
         else
            cli_thread = &cli_thread_tun4;
         break;
      case NOTUN_FIRST_MODE:
         if (state->dual_stack)
            cli_thread = &cli_thread_parallel46;
         else if (state->ipv6)
            cli_thread =  &cli_thread_notun6;
         else
            cli_thread =  &cli_thread_notun4;
         break;
      default:
         errno=EINVAL;
         die("cli_mode");
   }  
      

   /* initial sleep */
   sleep(state->initial_sleep);

   /* Client loop */
   for (int i=0; i<state->sa_len; i++) 
      (*cli_thread)(state, i);

   /* Shutdown client, not peer */
   if (args->mode == CLI_MODE)
      cli_shutdown(0);

   return 0;
}

void *serv_thread(void *st) {
   struct tun_state *state = st;
   serv_file = state->serv_file;

   /* fork servers */
   if (state->dual_stack) {
      xthread_create(serv_thread_private4, st, 1);
      xthread_create(serv_thread_public4,  st, 1);
      xthread_create(serv_thread_private6, st, 1);
      xthread_create(serv_thread_public6,  st, 1);
   } else if (state->ipv6) {
      xthread_create(serv_thread_private6, st, 1);
      xthread_create(serv_thread_public6,  st, 1);
   } else {
      xthread_create(serv_thread_private4, st, 1);
      xthread_create(serv_thread_public4,  st, 1);
   }

   return 0;
}

void *serv_thread_private4(void *st) {
   struct tun_state *state = st;
   tcp_serv(state->private_addr4, state->private_port, state, 
            state->max_segment_size, AF_INET);
   return 0;
}

void *serv_thread_private6(void *st) {
   struct tun_state *state = st;
   tcp_serv(state->private_addr6, state->private_port, state, 
            state->max_segment_size, AF_INET6);
   return 0;
}

void *serv_thread_public4(void *st) {
   struct tun_state *state = st;
   tcp_serv(state->public_addr4, state->public_port, state, 0, AF_INET);
   return 0;
}

void *serv_thread_public6(void *st) {
   struct tun_state *state = st;
   tcp_serv(state->public_addr6, state->public_port, state, 0, AF_INET6);
   return 0;
}

int tcp_serv(char *addr, int port, struct tun_state *state, 
               int set_maxseg, sa_family_t sfam) {
   int s;
   unsigned int sin_size;

   /* TCP socket */
   if ((s=socket(sfam, SOCK_STREAM, 0)) < 0) 
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
   size_t salen;
   struct sockaddr *sout, *sin;
   if (sfam == AF_INET6) {
      sout  = (struct sockaddr *)get_addr6(addr, port);
      salen = sizeof(struct sockaddr_in6);
      sin   = xmalloc(sizeof(struct sockaddr_in6));
   } else {
      sout  = (struct sockaddr *)get_addr4(addr, port);
      salen = sizeof(struct sockaddr_in);
      sin   = xmalloc(sizeof(struct sockaddr_in));
   }

   if (bind(s, sout, salen) < 0) {
      debug_print("died binding %s:%d ...\n", addr ? addr : "*", port);
      die("bind tcp server");
   }
   if (listen(s, state->backlog_size) < 0) 
      die("listen");

   /* listen loop */
   debug_print("TCP server listening at %s:%d ...\n", addr ? addr : "*", port);
   int success = 0, ws;
   char accepted_addr[INET6_ADDRSTRLEN];
   while(!success) {

      sin_size = salen;
      if ((ws = accept(s, sin, &sin_size)) < 0) 
         die("accept");

      if (sfam == AF_INET6)
         debug_print("accepted connection from %s on socket %d.\n", 
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sin)->sin6_addr, 
                                 accepted_addr, INET6_ADDRSTRLEN), ws);
      else
         debug_print("accepted connection from %s on socket %d.\n", 
                        inet_ntoa(((struct sockaddr_in *)sin)->sin_addr), ws);


      /* Fork worker thread */
      xthread_create(serv_worker_thread, (void*) &ws, 1);
   }

   close(s);
   free(sout);free(sin);
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
            char *addr, int port, int tun, char* filename, sa_family_t sfam) {
   struct tun_state *state = st;
   int s, err = 0; 
   FILE *fp = NULL;
   /* TCP socket */
   if ((s=socket(sfam, SOCK_STREAM, IPPROTO_TCP)) == -1) 
      die("socket");
   set_fd(s);

   /* Socket opts */
   struct timeval snd_timeout = {state->tcp_snd_timeout, 0}; 
   struct timeval rcv_timeout = {state->tcp_rcv_timeout, 0}; 
   if (setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout,
                sizeof(rcv_timeout)) < 0)
      debug_print("setsockopt rcvtimeo");
   if (setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &snd_timeout,
                sizeof(snd_timeout)) < 0)
      debug_print("setsockopt sndtimeo");

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
   size_t salen;
   struct sockaddr *sout;
   if (sfam == AF_INET6) {
      sout  = (struct sockaddr *)get_addr6(addr, port);
      salen = sizeof(struct sockaddr_in6);
   } else {
      sout  = (struct sockaddr *)get_addr4(addr, port);
      salen = sizeof(struct sockaddr_in);
   }

   if (bind(s, (struct sockaddr *)sout, salen) < 0) 
      die("bind tcp cli");
   debug_print("TCP cli bound to %s:%d\n", addr, port);

   /* connect peer */
   debug_print("connecting socket %d\n", s);
   if (connect(s, sa, salen) < 0) {     
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
   fclose(fp);close(s);free(sout);
   mode_t m = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
   if (chmod(filename, m) < 0)
      die("chmod");

   debug_print("socket %d successfuly closed.\n", s);
   return 0;
err:
   if (fp) fclose(fp); 
   close(s);free(sout);
   debug_print("socket %d closed on error: %s\n", s, strerror(err));
   return -1;
}

