/**
 * \file cli.c
 * \brief The client implementation.
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

#include "cli.h"
#include "debug.h"
#include "state.h"
#include "thread.h"
#include "sock.h"
#include "net.h"
#include "xpcap.h"

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

static void *cli_capture_tun(void *arg);
static void *cli_capture_notun(void *arg);

void cli_shutdown(int sig) { 
   debug_print("shutting down client ...\n");

   /* Wait for delayed acks to avoid sending icmp */
   sleep(__CLOSE_TIMEOUT);
   loop = 0; 
}

void tun_cli_in(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {//TODO remove useless args, maybe pass struct args for faster mode lookup

   int recvd=xread(fd_tun, buf, __BUFFSIZE);
   debug_print("cli: recvd %db from tun\n", recvd);

   /* Remove PlanetLab TUN PPI header */
   if (state->planetlab) {
      buf+=4;recvd-=4;
   }

   // lookup initial server database from file 
   struct tun_rec *rec = NULL; 
   in_addr_t priv_addr = (int) *((uint32_t *)(buf+16));
   debug_print("%s\n", inet_ntoa((struct in_addr){priv_addr}));

   /* lookup private addr */
   if ( (rec = g_hash_table_lookup(state->cli, &priv_addr)) ) {

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
         /* Add PlanetLab TUN PPI header */
         if (state->planetlab) {
            buf-=4; recvd+=4;
         }

         int sent = xwrite(fd_tun, buf, recvd);
         debug_print("cli: wrote %db to tun\n",sent);    
      } else debug_print("recvd empty pkt\n");
   }
}

void *cli_capture_tun(void *arg) {
   struct tun_state *state = (struct tun_state *)arg;
   char file_loc[512];
   strncpy(file_loc, state->out_dir, 512);
   
   strncat(file_loc, CLI_PCAP_FILE, 512);
   strncat(file_loc, "tun", 512);
   strncat(file_loc, ".id", 512);
   strncat(file_loc, ".pcap", 512);
   debug_print("%s\n", file_loc);
   xcapture(state->if_name, state->private_addr, 0, file_loc);
}

void *cli_capture_notun(void *arg) {
   struct tun_state *state = (struct tun_state *)arg;
   char file_loc[512];
   strncpy(file_loc, state->out_dir, 512);
   
   strncat(file_loc, CLI_PCAP_FILE, 512);
   strncat(file_loc, "notun", 512);
   strncat(file_loc, ".id", 512);
   strncat(file_loc, ".pcap", 512);
   debug_print("%s\n", file_loc);
   xcapture(state->default_if, state->public_addr, state->public_port, file_loc);
}

void tun_cli(struct arguments *args) {
   int fd_tun = 0, fd_udp = 0, fd_max = 0, sel = 0;
   
   /* init state */
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */   
   tun(state, &fd_tun);
   fd_udp   = udp_sock(state->port);

   xthread_create(cli_capture_tun, (void *) state);
   xthread_create(cli_capture_notun, (void *) state);

   /* initial sleep */
   sleep(state->initial_sleep);

   /* run client */
   debug_print("running cli ...\n");    
   xthread_create(cli_thread, (void*) state);

   /* init select loop */
   fd_set input_set;
   struct timeval tv;
   char buf[__BUFFSIZE], *buffer;
   buffer=buf;
   if (state->planetlab) {
      buffer[0]=0;buffer[1]=0;
      buffer[2]=8;buffer[3]=0;
      buffer+=4;
   }

   fd_max = max(fd_udp, fd_tun);
   loop = 1;
   signal(SIGINT, cli_shutdown);

   while (loop) {
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);
      FD_SET(fd_tun, &input_set);

      sel = xselect(&input_set, fd_max, &tv, state->inactivity_timeout);

      if (sel == 0) {
         debug_print("timeout\n"); 
         break;
      } else if (sel > 0) {
         if (FD_ISSET(fd_tun, &input_set))      
            tun_cli_in(fd_udp, fd_tun, state, buffer);
         if (FD_ISSET(fd_udp, &input_set)) 
            tun_cli_out(fd_udp, fd_tun, state, buffer);
      }
   }

   close(fd_udp);close(fd_tun);
   free_tun_state(state);
}

