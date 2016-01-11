/**
 * \file serv.c
 * \brief The server implementation.
 * \author k.edeline
 * \version 0.1
 */

#include "serv.h"
#include "state.h"
#include "destruct.h"

/**
 * \var static volatile int loop
 * \brief The server loop guardian.
 */
static volatile int loop;

/**
 * \fn static void serv_shutdown(int sig)
 * \brief Callback function for SIGINT catcher.
 *
 * \param sig Ignored
 */ 
static void serv_shutdown(int sig);

static void tun_serv_aux(struct arguments *args);
static void tun_serv_pl(struct arguments *args);
static void tun_serv_fbsd(struct arguments *args);

static void tun_peer_aux(struct arguments *args);
static void tun_peer_pl(struct arguments *args);
static void tun_peer_fbsd(struct arguments *args);

/**
 * \fn static void tun_serv_in(int fd_udp, int fd_tun, struct tun_state *state, char *buf)
 * \brief Forward a packet in the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_serv_in(int fd_udp, int fd_tun, struct tun_state *state, char *buf);

/**
 * \fn static void tun_serv_out(int fd_udp, int fd_tun, struct arguments *args, struct tun_state *state, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param args The arguments of the server.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_serv_out(int fd_udp, int fd_tun, struct arguments *args, struct tun_state *state, char *buf);

/**
 * \fn static build_sel(fd_set *input_set, int *fds_raw, int len, int *max_fd_raw)
 * \brief build a fd_set structure to be used with select() or similar.
 *
 * \param input_set modified on return to the fd_set.
 * \param fds_raw The fd to set.
 * \param len The number of fd.
 * \param max_fd_raw modified on return to indicate the max fd value.
 * \return 
 */ 
static void build_sel(fd_set *input_set, int *fds_raw, int len, int *max_fd_raw);

void serv_shutdown(int sig) { loop = 0; }

void tun_serv_in(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {

   int recvd=xread(fd_tun, buf, __BUFFSIZE);
   debug_print("serv: recvd %db from tun\n", recvd);

   if (recvd > 32) {

      struct tun_rec *rec = NULL; 
      //read sport for clients mapping
      int sport = (int) ntohs( *((uint16_t *)(buf+22)) ); 
      if (sport == state->tcp_port) {
         // lookup initial server database from file 
      } else if ( (rec = g_hash_table_lookup(state->serv, &sport)) ) {   
         debug_print("sport lookup: OK\n");

         int sent = xsendto(fd_udp, rec->sa, buf, recvd);
         debug_print("serv: wrote %db to udp\n",sent);
      } else {
         errno=EFAULT;
         die("lookup");
      }
   } 
}

void tun_serv_out(int fd_udp, int fd_tun, struct arguments *args, struct tun_state *state, char *buf) {
   //TODO don't die on reception error
   struct tun_rec *nrec = init_tun_rec();
   int recvd=xrecvfrom(fd_udp, (struct sockaddr *)nrec->sa, &nrec->slen, buf, __BUFFSIZE);

   debug_print("serv: recvd %db from udp\n", recvd);

   if (recvd > 32) {
      struct tun_rec *rec = NULL;
      int sport           = ntohs(((struct sockaddr_in *)nrec->sa)->sin_port);
      int sent            = 0;
      if ( (rec = g_hash_table_lookup(state->serv, &sport)) ) {
         //forward
         sent = xwrite(fd_tun, buf, recvd);
         free_tun_rec(nrec);
      } else if (g_hash_table_size(state->serv) <= state->fd_lim) { 
         sent = xwrite(fd_tun, buf, recvd);

         //add new record to lookup tables  
         nrec->sport = sport;
         g_hash_table_insert(state->serv, &nrec->sport, nrec);
         debug_print("serv: added new entry: %d\n", sport);
      } else {
         errno=EUSERS; //no need to exit but safer
         die("socket()");
      }
      debug_print("serv: wrote %d to tun\n", sent);     
   } else debug_print("recvd empty pkt\n");

}

void tun_serv(struct arguments *args) {
   if (args->planetlab)
      tun_serv_pl(args);
   else if (args->freebsd)
      tun_serv_fbsd(args);
   else
      tun_serv_aux(args);
}

void tun_serv_aux(struct arguments *args) {

   int fd_max = 0, fd_udp = 0, sel = 0, i = 0, fd_tun = 0;

   /* init server state */
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */
   args->if_name  = create_tun(state->private_addr, NULL, &fd_tun); 
   fd_udp         = udp_sock(state->udp_port);

   /* run server */
   debug_print("running serv ...\n");  
   pthread_t thread_id;
   if (pthread_create(&thread_id, NULL, serv_thread, (void*) state) < 0) 
      die("pthread_create serv_thread");
   set_pthread(thread_id);

   /* init select loop */
   fd_set input_set;
   struct timeval tv;
   char buf[__BUFFSIZE];

   fd_max=max(fd_tun,fd_udp);
   loop=1;
   signal(SIGINT, serv_shutdown);

   while (loop) {
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);
      FD_SET(fd_tun, &input_set);
      //TODO wrap up xselect  
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
         if (FD_ISSET(fd_udp, &input_set)) 
            tun_serv_out(fd_udp, fd_tun, args, state, buf);
         if (FD_ISSET(fd_tun, &input_set)) 
            tun_serv_in(fd_udp, fd_tun, state, buf);
      }
   }

   /* Close, free, ... */
   close(fd_udp);close(fd_tun);
   free_tun_state(state);
   free(args->if_name);
}

void tun_serv_fbsd(struct arguments *args) {


}

void tun_serv_pl(struct arguments *args) {
   int fd_max = 0, fd_udp = 0, sel = 0, i = 0, fd_tun = 0;

   //init tun itf
   const char *prefix = "24";
   struct tun_state *state = init_tun_state(args);
   char *if_name  = create_tun_pl(state->private_addr, prefix, 0, &fd_tun);

   //udp sock & dst sockaddr
   fd_udp   = udp_sock(state->udp_port);

   fd_set input_set;
   struct timeval tv;
   char buf[__BUFFSIZE];

   loop=1;
   signal(SIGINT, serv_shutdown);
   fd_max=max(fd_tun,fd_udp);
   while (loop) {
      //build select args
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);FD_SET(fd_tun, &input_set);

      tv.tv_sec  = 0; 
      tv.tv_usec = 0;

      sel = select(fd_max+1, &input_set, NULL, NULL, &tv);
      if (sel < 0) die("select");
      else if (sel > 0) {
         if (FD_ISSET(fd_udp, &input_set)) {
            tun_serv_out(fd_udp, fd_tun, args, state, buf);
         }
         if (FD_ISSET(fd_tun, &input_set)) {
            tun_serv_in(fd_udp, fd_tun, state, buf);
         }
      }
   }

   close(fd_udp);
   free_tun_state(state);
   free(if_name);
}

void build_sel(fd_set *input_set, int *fds_raw, int len, int *max_fd_raw) {
   int i = 0, max_fd = 0, fd = 0;
   FD_ZERO(input_set); //TODO move thus to sock
   for (;i<len;i++) {
      fd = fds_raw[i];
      if (fd) {
       FD_SET(fd, input_set);
       max_fd = max(fd,max_fd);
      } else break;
   }

   *max_fd_raw = max_fd;
}

