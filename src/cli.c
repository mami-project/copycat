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
 * \fn static void tun_cli_in(int fd_net, int fd_tun, struct sockaddr_in *udp_addr, char *buf)
 * \brief Forward a packet in the tunnel.
 *
 * \param fd_net The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param udp_addr The address of the udp target.
 * \param buf The buffer.
 */ 
static void tun_cli_in(int fd_tun, int fd_net4,  int fd_net6,
                       struct tun_state *state, char *buf);
static void tun_cli_in4(int fd_net, int fd_tun, 
                        struct tun_state *state, char *buf);
static void tun_cli_in6(int fd_net, int fd_tun, 
                        struct tun_state *state, char *buf);
static void tun_cli_in4_aux(int fd_net, struct tun_state *state, char *buf, int recvd);
static void tun_cli_in6_aux(int fd_net, struct tun_state *state, char *buf, int recvd);

/**
 * \fn static void tun_cli_out4(int fd_net, int fd_tun, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_net The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param buf The buffer. 
 */ 
static void tun_cli_out4(int fd_net, int fd_tun, struct tun_state *state, char *buf);
static void tun_cli_out6(int fd_net, int fd_tun, struct tun_state *state, char *buf);

static void tun_cli_single(struct arguments *args);
static void tun_cli_dual(struct arguments *args);


void cli_shutdown(int UNUSED(sig)) { 
   debug_print("shutting down client ...\n");

   /* Wait for delayed acks to avoid sending icmps */
   sleep(CLOSE_TIMEOUT);
   loop = 0; 
}

void tun_cli(struct arguments *args) {
   

   if (args->dual_stack)
      tun_cli_dual(args);
   else
      tun_cli_single(args);
}

void tun_cli_in(int fd_tun, int fd_net4, int fd_net6,
                struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("recvd %db from tun\n", recvd);

   switch (buf[0] & 0xf0) {
      case 0x40:
         tun_cli_in4_aux(fd_net4, state, buf, recvd);
         break;
      case 0x60:
         tun_cli_in6_aux(fd_net6, state, buf, recvd);
         break;
      default:
         debug_print("non-ip proto:%d\n", buf[0]);
         break;
   }
}

void tun_cli_in6(int fd_net, int fd_tun, 
                 struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("recvd %db from tun\n", recvd);
   tun_cli_in6_aux(fd_net, state, buf, recvd);
}

void tun_cli_in4(int fd_net, int fd_tun, 
                 struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("recvd %db from tun\n", recvd);
   tun_cli_in4_aux(fd_net, state, buf, recvd);
}

void tun_cli_in4_aux(int fd_net, struct tun_state *state, char *buf, int recvd) {

   /* lookup initial server database from file */
   struct tun_rec *rec = NULL; 
   in_addr_t priv_addr4 = (int) *((uint32_t *)(buf+16));
   debug_print("%s\n", inet_ntoa((struct in_addr){priv_addr4}));

   /* lookup private addr */
   if ( (rec = g_hash_table_lookup(state->cli4, &priv_addr4)) ) {

      /* Remove PlanetLab TUN PPI header */
      if (state->planetlab) {
         recvd-=4;
         memmove(buf, buf+4, recvd);
      }
      /* Add layer 4.5 header */
      if (state->raw_header) {
         buf -= state->raw_header_size;
         recvd += state->raw_header_size;
      }

      int sent = xsendto4(fd_net, rec->sa4, buf, recvd);
      debug_print("cli: wrote %dB to internet\n",sent);

   } else {
      debug_print("lookup failed proto:%d sport:%d dport:%d\n", 
                   (int) *((uint8_t *)(buf+9)), 
                   (int) ntohs( *((uint16_t *)(buf+20)) ), 
                   (int)ntohs( *((uint16_t *)(buf+22)) ));
   }
}

void tun_cli_in6_aux(int fd_net, struct tun_state *state, char *buf, int recvd) {
   struct tun_rec *rec = NULL; 

   /* lookup initial server database from file */
   char priv_addr6[16], str_addr6[INET6_ADDRSTRLEN];
   memcpy(priv_addr6, buf+24, 16);
   debug_print("%s\n", inet_ntop(AF_INET6, priv_addr6, 
                         str_addr6, INET6_ADDRSTRLEN));

   /* lookup private addr */
   if ( (rec = g_hash_table_lookup(state->cli6, priv_addr6)) ) {

      /* Remove PlanetLab TUN PPI header */
      if (state->planetlab) {
         recvd-=4;
         memmove(buf, buf+4, recvd);
      }
      /* Add layer 4.5 header */
      if (state->raw_header) {
         buf -= state->raw_header_size;
         recvd += state->raw_header_size;
      }

      int sent = xsendto6(fd_net, rec->sa6, buf, recvd);
      debug_print("cli: wrote %dB to udp\n",sent);

   } else {
      debug_print("lookup failed proto:%d sport:%d dport:%d\n", 
                   (int) *((uint8_t *)(buf+6)), 
                   (int) ntohs( *((uint16_t *)(buf+40)) ), 
                   (int)ntohs( *((uint16_t *)(buf+42)) ));
   }
}

void tun_cli_out4(int fd_net, int fd_tun, struct tun_state *state, char *buf) {
   int recvd = xrecv(fd_net, buf, BUFF_SIZE);

   if (recvd > MIN_PKT_SIZE) {
      debug_print("cli: recvd %dB from internet\n", recvd);

      /* Remove layer 4.5 header */
      if (state->raw_header) {
         if (!state->udp)
            recvd -= 20; 
         recvd -= state->raw_header_size;
         memmove(buf, buf+state->raw_header_size, recvd);
      }
      /* Add PlanetLab TUN PPI header */
      if (state->planetlab) {
         buf-=4; recvd+=4;
      }

      int sent = xwrite(fd_tun, buf, recvd);
      debug_print("cli: wrote %dB to tun\n", sent);
   } else if (recvd < 0) {
      /* recvd ICMP msg */
      xrecverr(fd_net, buf, BUFF_SIZE, 0, NULL);
   } else {
      /* recvd unknown packet */
      debug_print("recvd empty pkt\n");
   }   
}

void tun_cli_out6(int fd_net, int fd_tun, struct tun_state *state, char *buf) {
   int recvd = xrecv(fd_net, buf, BUFF_SIZE);

   if (recvd > MIN_PKT_SIZE) {
      debug_print("cli: recvd %dB from internet\n", recvd);

      /* Remove layer 4.5 header */
      if (state->raw_header) {
         if (!state->udp)
            recvd -= 40; 
         recvd -= state->raw_header_size;
         memmove(buf, buf+state->raw_header_size, recvd);
      }
      /* Add PlanetLab TUN PPI header */
      if (state->planetlab) {
         buf-=4; recvd+=4;
      }

      int sent = xwrite(fd_tun, buf, recvd);
      debug_print("cli: wrote %dB to tun\n", sent);
   } else if (recvd < 0) {
      /* recvd ICMP msg */
      xrecverr(fd_net, buf, BUFF_SIZE, 0, NULL);
   } else {
      /* recvd unknown packet */
      debug_print("recvd empty pkt\n");
   }   
}

void tun_cli_single(struct arguments *args) {
   int fd_tun = 0, fd_net = 0; 
   void (*tun_cli_in_func)(int,int,struct tun_state*,char*);
   void (*tun_cli_out_func)(int,int,struct tun_state*,char*);

   /* init state */
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */   
   tun(state, &fd_tun);
   if (state->ipv6) {
      if (state->udp)
         fd_net = udp_sock6(state->port, 1, state->public_addr6);
      else
         fd_net = raw_sock6(state->port, state->public_addr6, 
                            gen_bpf(state->default_if, state->public_addr6, 
                                    state->port, 0), 
                             state->default_if, state->protocol_num, 
                            1, state->planetlab);
      tun_cli_in_func = &tun_cli_in6;
      tun_cli_out_func = &tun_cli_out6;
   } else {
      if (state->udp)
         fd_net = udp_sock4(state->port, 1, state->public_addr4);
      else
         fd_net = raw_sock4(state->port, state->public_addr4, 
                            gen_bpf(state->default_if, state->public_addr4, 
                                    state->port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
      tun_cli_in_func = &tun_cli_in4;
      tun_cli_out_func = &tun_cli_out4;
   }

   /* run capture threads */
   xthread_create(capture_notun, (void *) state, 1);
   synchronize();

   /* run client */
   debug_print("running cli ...\n");    
   xthread_create(cli_thread, (void*) state, 1);

   /* init select loop */
   fd_set input_set;
   struct timeval tv;
   int sel = 0, fd_max = 0;
   char inbuf[BUFF_SIZE], outbuf[BUFF_SIZE];
   char *inbuffer, *outbuffer;
   inbuffer = inbuf;
   outbuffer = outbuf;

   if (state->raw_header) {
      memcpy(inbuffer, state->raw_header, state->raw_header_size);
      inbuffer += state->raw_header_size;
   }
   if (state->planetlab) {
      outbuffer[0]=0;outbuffer[1]=0;
      outbuffer[2]=8;outbuffer[3]=0;
      outbuffer += 4;
   }

   fd_max = max(fd_net, fd_tun);
   loop = 1;
   signal(SIGINT, cli_shutdown);
   signal(SIGTERM, cli_shutdown);

   while (loop) {
      FD_ZERO(&input_set);
      FD_SET(fd_net, &input_set);
      FD_SET(fd_tun, &input_set);

      sel = xselect(&input_set, fd_max, &tv, state->inactivity_timeout);

      if (sel == 0) {
         debug_print("timeout\n"); 
         break;
      } else if (sel > 0) {
         if (FD_ISSET(fd_tun, &input_set)) { 
            (*tun_cli_in_func)(fd_net, fd_tun, state, inbuffer);}
         if (FD_ISSET(fd_net, &input_set)) 
            (*tun_cli_out_func)(fd_net, fd_tun, state, outbuffer);
      }
   }
}

void tun_cli_dual(struct arguments *args) {
   int fd_tun = 0, fd_net4 = 0, fd_net6 = 0; 
   void (*tun_cli_in_func)(int,int,struct tun_state*,char*);

   /* init state */
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */   
   tun(state, &fd_tun);
   if (state->udp) {
      fd_net4 = udp_sock4(state->public_port, 1, state->public_addr4);
      fd_net6 = udp_sock6(state->public_port, 1, state->public_addr6);
   } else {
      fd_net4 = raw_sock4(state->public_port, state->public_addr4, 
                            gen_bpf(state->default_if, state->public_addr4, 
                                    state->port, 0), state->default_if, 
                            state->protocol_num, 
                            1, state->planetlab);
      fd_net6 = raw_sock6(state->public_port, state->public_addr6, 
                            gen_bpf(state->default_if, state->public_addr6, 
                                    state->port, 0), state->default_if, 
                            state->protocol_num, 
                            1, state->planetlab);
   }

   /* run capture threads */
   xthread_create(capture_notun, (void *) state, 1);
   synchronize();

   /* run client */
   debug_print("running cli ...\n");    
   xthread_create(cli_thread, (void*) state, 1);

   /* init select loop */
   fd_set input_set;
   struct timeval tv;
   int sel = 0, fd_max = 0;
   char inbuf[BUFF_SIZE], outbuf[BUFF_SIZE];
   char *inbuffer, *outbuffer;
   inbuffer = inbuf;
   outbuffer = outbuf;

   if (state->raw_header) {
      memcpy(inbuffer, state->raw_header, state->raw_header_size);
      inbuffer += state->raw_header_size;
   }
   if (state->planetlab) {
      outbuffer[0]=0;outbuffer[1]=0;
      outbuffer[2]=8;outbuffer[3]=0;
      outbuffer += 4;
   }

   fd_max = max(max(fd_net4, fd_net6), fd_tun);
   loop = 1;
   signal(SIGINT, cli_shutdown);
   signal(SIGTERM, cli_shutdown);

   while (loop) {
      FD_ZERO(&input_set);
      FD_SET(fd_net4, &input_set);
      FD_SET(fd_net6, &input_set);
      FD_SET(fd_tun, &input_set);

      sel = xselect(&input_set, fd_max, &tv, state->inactivity_timeout);

      if (sel == 0) {
         debug_print("timeout\n"); 
         break;
      } else if (sel > 0) {
         if (FD_ISSET(fd_tun, &input_set))      
            tun_cli_in(fd_tun, fd_net4, fd_net6, state, inbuffer);
         if (FD_ISSET(fd_net4, &input_set)) 
            tun_cli_out4(fd_net4, fd_tun, state, outbuffer);
         if (FD_ISSET(fd_net6, &input_set)) 
            tun_cli_out6(fd_net6, fd_tun, state, outbuffer);
      }
   }
}

