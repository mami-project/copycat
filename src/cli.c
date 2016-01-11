/**
 * \file cli.c
 * \brief The client implementation.
 * \author k.edeline
 * \version 0.1
 */

#include <pthread.h>

#include "cli.h"
#include "state.h"
#include "destruct.h"

/**
 * \var static volatile int loop
 * \brief The client loop guardian.
 */
static volatile int loop;

/**
 * \fn static void tun_cli_in(int fd_udp, int fd_tun, struct sockaddr_in *udp_addr, char *buf)
 * \brief Forward a packet in the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param udp_addr The address of the udp target.
 * \param buf The buffer.
 */ 
static void tun_cli_in(int fd_udp, int fd_tun, struct tun_state *state, char *buf);

/**
 * \fn static void tun_cli_out(int fd_udp, int fd_tun, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param buf The buffer. 
 */ 
static void tun_cli_out(int fd_udp, int fd_tun, struct tun_state *state, char *buf);

static void tun_cli_aux(struct arguments *args);
static void tun_cli_pl(struct arguments *args);
static void tun_cli_fbsd(struct arguments *args);

void cli_shutdown(int sig) { 
   debug_print("shutting down client ...\n");

   /* Wait for delayed acks to avoid sending icmp */
   sleep(__CLOSE_TIMEOUT);

   loop = 0; 
}

void tun_cli_in(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {

      int recvd=xread(fd_tun, buf, __BUFFSIZE);
      debug_print("cli: recvd %db from tun\n", recvd);

      // lookup initial server database from file 
      struct tun_rec *rec = NULL; 
      in_addr_t priv_addr = (int) *((uint32_t *)(buf+16));
      debug_print("%s\n", inet_ntoa((struct in_addr){priv_addr}));

      /* lookup private addr */
      if ( (rec = g_hash_table_lookup(state->cli, &priv_addr)) ) {
         debug_print("priv addr lookup: OK\n");

         int sent = xsendto(fd_udp, rec->sa, buf, recvd);
         debug_print("cli: wrote %db to udp\n",sent);

      } else {
         errno=EFAULT;
         die("cli lookup");
      }
}

void tun_cli_out(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {
   int recvd = 0;
   if ( (recvd=xrecv(fd_udp, buf, __BUFFSIZE)) < 0) {
      /* recvd ICMP msg */
      //xfwerr(fd_udp, buf,  __BUFFSIZE, fd_tun, state);
      xrecverr(fd_udp, buf,  __BUFFSIZE);
   } else {
      debug_print("cli: recvd %db from udp\n", recvd);

      if (recvd > 32) {
         int sent = xwrite(fd_tun, buf, recvd);

         debug_print("cli: wrote %db to tun\n",sent);    
      } else debug_print("recvd empty pkt\n");
   }
}

void tun_cli(struct arguments *args) {
   if (args->planetlab)
      tun_cli_pl(args);
   else if (args->freebsd)
      tun_cli_fbsd(args);
   else
      tun_cli_aux(args);
}

void tun_cli_aux(struct arguments *args) {
   int fd_tun = 0, fd_udp = 0, fd_tcp = 0;
   int fd_max = 0, sel = 0;
   
   /* init state */
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */   
   args->if_name  = create_tun(state->private_addr, NULL, &fd_tun);   
   fd_udp   = udp_sock(state->port);

   /* initial sleep */
   sleep(state->initial_sleep);

   /* run client */
   pthread_t thread_id;
   if (pthread_create(&thread_id, NULL, cli_thread, (void*) state) < 0) 
      die("pthread_create");
   set_pthread(thread_id);

   /* init select loop */
   fd_set input_set;
   struct timeval tv;
   char buf[__BUFFSIZE];
   fd_max = max(fd_udp, fd_tun);
   loop = 1;
   signal(SIGINT, cli_shutdown);

   while (loop) {
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);
      FD_SET(fd_tun, &input_set);

      if (state->inactivity_timeout != -1) {
         tv.tv_sec  = state->inactivity_timeout;
         tv.tv_usec = 0;
         sel = select(fd_max+1, &input_set, NULL, NULL, &tv);
      } else 
         sel = select(fd_max+1, &input_set, NULL, NULL, NULL);

      if (sel < 0) die("select");
      else if (sel == 0) {
         debug_print("timeout\n"); 
         break;
      } else if (sel > 0) {
         if (FD_ISSET(fd_tun, &input_set))      
            tun_cli_in(fd_udp, fd_tun, state, buf);
         if (FD_ISSET(fd_udp, &input_set)) 
            tun_cli_out(fd_udp, fd_tun, state, buf);
      }
   }

   close(fd_udp);close(fd_tun);
   free(args->if_name);
   
}

void tun_cli_fbsd(struct arguments *args) {
   // init tun itf
   int fd_tun     = 0;

}

void tun_cli_pl(struct arguments *args) {
   int fd_max = 0, fd_udp = 0, fd_tun = 0, sel = 0;
   char *if_name = NULL;
   struct sockaddr_in *udp_addr = NULL, *tcp_addr = NULL;
   struct sock_fprog *bpf = NULL;

   //init tun itf
   const char *prefix = "24";
   int tun_fd = 0;
   struct tun_state *state = init_tun_state(args);
   if_name  = create_tun_pl(state->private_addr, prefix, 0, &tun_fd);
   //udp sock & dst sockaddr

   fd_udp   = udp_sock(state->port);
   udp_addr = get_addr(state->public_addr, state->udp_port);


   loop = 1;
   signal(SIGINT, cli_shutdown);

   fd_set input_set;
   fd_max = max(fd_udp, tun_fd);
   struct timeval tv;
   char buf[__BUFFSIZE];

   debug_print("main loop\n");
   while (loop) {
      //build select list
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);FD_SET(tun_fd, &input_set);

      tv.tv_sec  = state->inactivity_timeout; 
      tv.tv_usec = 0;

      sel = select(fd_max+1, &input_set, NULL, NULL, &tv);
      if (sel < 0) die("select");
      else if (sel > 0) {
         if (FD_ISSET(fd_tun, &input_set))      
            tun_cli_in(fd_udp, fd_tun, state, buf);
         if (FD_ISSET(fd_udp, &input_set)) 
            tun_cli_out(fd_udp, fd_tun, state, buf);
      }
   }

   close(fd_udp);
   free(if_name);free(udp_addr);free((struct bpf_program *)bpf);
}

