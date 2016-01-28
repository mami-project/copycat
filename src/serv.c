/**
 * \file serv.c
 * \brief The server implementation.
 * \author k.edeline
 * \version 0.1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "serv.h"
#include "debug.h"
#include "state.h"
#include "sock.h"
#include "thread.h"
#include "net.h"
#include "xpcap.h"

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
 * \fn static void tun_serv_out(int fd_udp, int fd_tun, struct tun_state *state, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_serv_out(int fd_udp, int fd_tun, struct tun_state *state, char *buf);

void serv_shutdown(int UNUSED(sig)) { loop = 0; }

void tun_serv_in(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {

   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("serv: recvd %db from tun\n", recvd);

   /* Remove PlanetLab TUN PPI header */
   if (state->planetlab) {
      buf+=4;recvd-=4;
   }

   if (recvd > 32) {

      struct tun_rec *rec = NULL; 
      /* read sport for clients mapping */
      int sport = (int) ntohs( *((uint16_t *)(buf+22)) ); 
      if ( (rec = g_hash_table_lookup(state->serv, &sport)) ) {   

         int sent = xsendto(fd_udp, rec->sa, buf, recvd);
         debug_print("serv: wrote %db to udp\n",sent);
      } else {
         errno=EFAULT;
         die("lookup");
      }
   } 
}

void tun_serv_out(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {
   struct tun_rec *nrec = init_tun_rec();
   int recvd=xrecvfrom(fd_udp, (struct sockaddr *)nrec->sa, &nrec->slen, buf, BUFF_SIZE);
   debug_print("serv: recvd %db from udp\n", recvd);

   /* Add PlanetLab TUN PPI header */
   if (state->planetlab) {
      buf-=4; recvd+=4;
   }

   if (recvd > 32) {
      struct tun_rec *rec = NULL;
      int sport           = ntohs(((struct sockaddr_in *)nrec->sa)->sin_port);
      int sent            = 0;
      if ( (rec = g_hash_table_lookup(state->serv, &sport)) ) {
         /* forward */
         sent = xwrite(fd_tun, buf, recvd);
         free_tun_rec(nrec);
      } else if (g_hash_table_size(state->serv) <= state->fd_lim) { 
         sent = xwrite(fd_tun, buf, recvd);

         /* add new record to lookup tables */
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
   int fd_max = 0, fd_udp = 0, sel = 0, fd_tun = 0;

   /* init server state */
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */
   tun(state, &fd_tun); 
   fd_udp         = udp_sock(state->public_port);

   xthread_create(capture_tun, (void *) state, 1);
   xthread_create(capture_notun, (void *) state, 1);
   synchronize();

   /* run server */
   debug_print("running serv ...\n");  
   xthread_create(serv_thread, (void*) state, 1);

   /* init select loop */
   fd_set input_set;
   struct timeval tv;
   char buf[BUFF_SIZE], *buffer;
   buffer=buf;
   if (state->planetlab) {
      buffer[0]=0;buffer[1]=0;
      buffer[2]=8;buffer[3]=0;
      buffer+=4;
   }

   fd_max=max(fd_tun,fd_udp);
   loop=1;
   signal(SIGINT, serv_shutdown);
   signal(SIGTERM, serv_shutdown);

   while (loop) {
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);
      FD_SET(fd_tun, &input_set);
  
      sel = xselect(&input_set, fd_max, &tv, state->inactivity_timeout);

      if (sel == 0) {
         debug_print("timeout\n"); 
         break;
      } else if (sel > 0) {
         if (FD_ISSET(fd_udp, &input_set)) 
            tun_serv_out(fd_udp, fd_tun, state, buffer);
         if (FD_ISSET(fd_tun, &input_set)) 
            tun_serv_in(fd_udp, fd_tun, state, buffer);
      }
   }

   /* Close, free, ... */
   close(fd_udp);close(fd_tun);
}

