/**
 * \file peer.c
 * \brief The fullmesh peer implementation.
 * \author k.edeline
 * \version 0.1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <glib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "peer.h"
#include "debug.h"
#include "state.h"
#include "thread.h"
#include "sock.h"
#include "net.h"
#include "xpcap.h"

/**
 * \var static volatile int loop
 * \brief The server loop guardian.
 */
static volatile int loop;

/**
 * \fn static void peer_shutdown(int sig)
 * \brief Callback function for SIGINT catcher.
 *
 * \param sig Ignored
 */ 
static void peer_shutdown(int sig);

/**
 * \fn static void tun_serv_in(int fd_udp, int fd_tun, struct tun_state *state, char *buf)
 * \brief Forward a packet in the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_peer_in(int fd_tun, int fd_cli, int fd_serv, struct tun_state *state, char *buf);

/**
 * \fn static void tun_serv_out(int fd_udp, int fd_tun, struct arguments *args, struct tun_state *state, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_peer_out_cli(int fd_udp, int fd_tun, struct tun_state *state, char *buf);

/**
 * \fn static void tun_serv_out(int fd_udp, int fd_tun, struct arguments *args, struct tun_state *state, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_peer_out_serv(int fd_udp, int fd_tun, struct tun_state *state, char *buf);

void peer_shutdown(int sig) { loop = 0; }

void tun_peer_in(int fd_tun, int fd_cli, int fd_serv, struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, __BUFFSIZE);
   debug_print("recvd %db from tun\n", recvd);

   if (recvd > 32) {

      /* Remove PlanetLab TUN PPI header */
      if (state->planetlab) {
         buf+=4;recvd-=4;
      }

      struct tun_rec *rec = NULL; 
      //read sport for clients mapping
      int dport = (int) ntohs( *((uint16_t *)(buf+22)) ); // 26 with PI

      /* cli */
      if (dport == state->private_port) {
         /* lookup initial server database from file */
         in_addr_t priv_addr = (int) *((uint32_t *)(buf+16));
         debug_print("%s\n", inet_ntoa((struct in_addr){priv_addr}));
         /* lookup private addr */
         if ( (rec = g_hash_table_lookup(state->cli, &priv_addr)) ) {
            debug_print("priv addr lookup: OK\n");

            int sent = xsendto(fd_cli, rec->sa, buf, recvd);
            debug_print("wrote %db to udp\n",sent);

         } else {
            errno=EFAULT;
            die("cli lookup");
         }

      /* serv */
      } else if ((rec = g_hash_table_lookup(state->serv, &dport))) {   

         int sent = xsendto(fd_serv, rec->sa, buf, recvd);
         debug_print("wrote %db to udp\n",sent);
      } else {
         errno=EFAULT;
         die("serv lookup");
      }
   } 
}

void tun_peer_out_cli(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {
   int recvd = 0;
   if ( (recvd=xrecv(fd_udp, buf, __BUFFSIZE)) < 0) {
      /* recvd ICMP msg */
      //xfwerr(fd_udp, buf,  __BUFFSIZE, fd_tun, state);
      xrecverr(fd_udp, buf,  __BUFFSIZE);
   } else {
      debug_print("recvd %db from udp\n", recvd);

      if (recvd > 32) {

         /* Add PlanetLab TUN PPI header */
         if (state->planetlab) {
            buf-=4; recvd+=4;
         }

         int sent = xwrite(fd_tun, buf, recvd);
         debug_print("wrote %d to tun\n", sent);     
      } else debug_print("recvd empty pkt\n");
   }
}

void tun_peer_out_serv(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {
   struct tun_rec *nrec = init_tun_rec();
   int recvd = 0;
   recvd=xrecvfrom(fd_udp, (struct sockaddr *)nrec->sa, &nrec->slen, buf, __BUFFSIZE);
   debug_print("recvd %db from udp\n", recvd);

   /* Add PlanetLab TUN PPI header */
   if (state->planetlab) {
      buf-=4; recvd+=4;
   }

   if (recvd > 32) {
      struct tun_rec *rec = NULL;
      int sport           = ntohs(((struct sockaddr_in *)nrec->sa)->sin_port);
      int sent            = 0;
      if ( (rec = g_hash_table_lookup(state->serv, &sport)) ) {
         sent = xwrite(fd_tun, buf, recvd);
         free_tun_rec(nrec);
      } else if (g_hash_table_size(state->serv) <= state->fd_lim) { 
         sent = xwrite(fd_tun, buf, recvd);

         //add new record to lookup tables  
         nrec->sport = sport;
         g_hash_table_insert(state->serv, &nrec->sport, nrec);
         debug_print("serv: added new entry: %d\n", sport);
      } else {
         free_tun_rec(nrec);
         errno=EUSERS; //no need to exit but safer
         die("socket()");
      }
      debug_print("serv: wrote %d to tun\n", sent);     
   } else {
      debug_print("recvd empty pkt\n");
      free_tun_rec(nrec);
   }

}

void tun_peer(struct arguments *args) {
   int fd_tun = 0, fd_serv = 0, fd_cli = 0;
   int fd_max = 0, sel = 0;
   
   /* init state */
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */
   tun(state, &fd_tun);   
   fd_serv        = udp_sock(state->public_port);
   fd_cli         = udp_sock(state->port);

   /* run capture threads */
   xthread_create(capture_tun, (void *) state);
   xthread_create(capture_notun, (void *) state);
   synchronize();

   /* run server */
   debug_print("running serv ...\n");  
   xthread_create(serv_thread, (void*) state);

   /* initial sleep */
   sleep(state->initial_sleep);

   /* run client */
   debug_print("running cli ...\n"); 
   xthread_create(cli_thread, (void*) state);

   /* init select main loop */
   fd_set input_set;
   struct timeval tv;
   char buf[__BUFFSIZE], *buffer;
   buffer=buf;
   if (state->planetlab) {
      buffer[0]=0;buffer[1]=0;
      buffer[2]=8;buffer[3]=0;
      buffer+=4;
   }

   fd_max = max(max(fd_cli, fd_tun), fd_serv);
   loop   = 1;
   signal(SIGINT, peer_shutdown);
   signal(SIGTERM, peer_shutdown);

   while (loop) {
      FD_ZERO(&input_set);
      FD_SET(fd_cli,  &input_set);
      FD_SET(fd_serv, &input_set);
      FD_SET(fd_tun,  &input_set);

      sel = xselect(&input_set, fd_max, &tv, state->inactivity_timeout);

      if (sel == 0) {
         debug_print("timeout\n"); 
         break;
      } else if (sel > 0) {
         if (FD_ISSET(fd_tun, &input_set))      
            tun_peer_in(fd_tun, fd_cli, fd_serv, state, buffer); 
         if (FD_ISSET(fd_cli, &input_set)) 
            tun_peer_out_cli(fd_cli, fd_tun, state, buffer);
         if (FD_ISSET(fd_serv, &input_set)) 
            tun_peer_out_serv(fd_serv, fd_tun, state, buffer);
      }
   }

   /* Close, free, ... */
   close(fd_cli);close(fd_serv);
   close(fd_tun);free_tun_state(state);
}

