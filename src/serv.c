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
 * \fn static void tun_serv_in(int fd_net, int fd_tun, struct tun_state *state, char *buf)
 * \brief Forward a packet in the tunnel.
 *
 * \param fd_net The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_serv_in4(int fd_tun, int fd_net, 
                         struct tun_state *state, char *buf);
static void tun_serv_in6(int fd_tun, int fd_net, 
                         struct tun_state *state, char *buf);
static void tun_serv_in4_aux(int fd_net, 
                             struct tun_state *state, char *buf, int recvd);
static void tun_serv_in6_aux(int fd_net, 
                             struct tun_state *state, char *buf, int recvd);
static void tun_serv_in(int fd_tun, int fd_net4, 
                 int fd_net6, struct tun_state *state, char *buf);

/**
 * \fn static void tun_serv_out(int fd_net, int fd_tun, struct tun_state *state, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_net The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_serv_out4(int fd_net, int fd_tun, struct tun_state *state, char *buf);
static void tun_serv_out6(int fd_net, int fd_tun, struct tun_state *state, char *buf);

static void tun_serv_single(struct arguments *args);
static void tun_serv_dual(struct arguments *args);

void serv_shutdown(int UNUSED(sig)) { loop = 0; }

void tun_serv(struct arguments *args) {
   if (args->dual_stack)
      tun_serv_dual(args);
   else
      tun_serv_single(args);
}

void tun_serv_in(int fd_tun, int fd_net4, 
                 int fd_net6, struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("recvd %db from tun\n", recvd);

   switch (buf[0] & 0xf0) {
      case 0x40:
         tun_serv_in4_aux(fd_net4, state, buf, recvd);
         break;
      case 0x60:
         tun_serv_in6_aux(fd_net6, state, buf, recvd);
         break;
      default:
         debug_print("non-ip proto:%d\n", buf[0]);
         break;
   }
}

void tun_serv_in4_aux(int fd_net, struct tun_state *state, char *buf, int recvd) {

   if (recvd > MIN_PKT_SIZE) {

      /* Remove PlanetLab TUN PPI header */
      if (state->planetlab) {
         recvd-=4;
         memmove(buf, buf+4, recvd);
      }

      struct tun_rec *rec = NULL; 
      /* read sport for clients mapping */
      int sport = (int) ntohs( *((uint16_t *)(buf+22)) ); 

      /* Add layer 4.5 header */
      if (state->raw_header) {
         buf -= state->raw_header_size;
         recvd += state->raw_header_size;
      }

      if ( (rec = g_hash_table_lookup(state->serv, &sport)) ) {   

         int sent = xsendto4(fd_net, rec->sa4, buf, recvd);
         debug_print("serv: wrote %dB to internet\n",sent);
      } else {
         errno=EFAULT;
         die("lookup");
      }
   }
}

void tun_serv_in6_aux(int fd_net, struct tun_state *state, char *buf, int recvd) {
 
   if (recvd > MIN_PKT_SIZE) {

      /* Remove PlanetLab TUN PPI header */
      if (state->planetlab) {
         recvd-=4;
         memmove(buf, buf+4, recvd);
      }

      struct tun_rec *rec = NULL; 
      /* read sport for clients mapping */
      int sport = (int) ntohs( *((uint16_t *)(buf+42)) ); 

      /* Add layer 4.5 header */
      if (state->raw_header) {
         buf -= state->raw_header_size;
         recvd += state->raw_header_size;
      }

      if ( (rec = g_hash_table_lookup(state->serv, &sport)) ) {   

         int sent = xsendto6(fd_net, rec->sa6, buf, recvd);
         debug_print("serv: wrote %dB to internet\n",sent);
      } else {
         errno=EFAULT;
         die("lookup");
      }
   }
}

void tun_serv_in6(int fd_tun, int fd_net, 
                 struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("recvd %db from tun\n", recvd);
   tun_serv_in6_aux(fd_net, state, buf, recvd);
}

void tun_serv_in4(int fd_tun, int fd_net, 
                 struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("recvd %db from tun\n", recvd);
   tun_serv_in4_aux(fd_net, state, buf, recvd);
}

void tun_serv_out4(int fd_net, int fd_tun, struct tun_state *state, char *buf) {
   struct tun_rec *nrec = init_tun_rec(state);
   int recvd = xrecvfrom(fd_net, (struct sockaddr *)nrec->sa4, 
                         &nrec->slen4, buf, BUFF_SIZE);

   if (recvd > MIN_PKT_SIZE) {
      debug_print("serv: recvd %dB from internet\n", recvd);

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

      struct tun_rec *rec = NULL;
      int sport           = ntohs(((struct sockaddr_in *)nrec->sa4)->sin_port);
      int sent            = 0;
      if ( (rec = g_hash_table_lookup(state->serv, &sport)) ) {
         sent = xwrite(fd_tun, buf, recvd);
         debug_print("serv: wrote %dB to tun\n", sent); 
      } 
#if !defined(LOCKED)
      else if (g_hash_table_size(state->serv) <= state->fd_lim) { 
         sent = xwrite(fd_tun, buf, recvd);

         /* add new record to lookup tables */
         nrec->sport = sport;
         g_hash_table_insert(state->serv, &nrec->sport, nrec);
         debug_print("serv: added new entry: %d\n", sport);
      } 
#endif
      else {
         debug_print("dropping unknown UDP dgram (NAT ?)\n");
      }
          
   } else if (recvd < 0) {
       /* recvd ICMP msg */
      xrecverr(fd_net, buf,  BUFF_SIZE, 0, NULL);
   } else {
      /* recvd unknown packet */
      debug_print("serv: recvd empty pkt\n");
   }
   free_tun_rec(nrec);
}

void tun_serv_out6(int fd_net, int fd_tun, struct tun_state *state, char *buf) {
   struct tun_rec *nrec = init_tun_rec(state);
   int recvd = xrecvfrom(fd_net, (struct sockaddr *)nrec->sa6, 
                         &nrec->slen6, buf, BUFF_SIZE);

   if (recvd > MIN_PKT_SIZE) {
      debug_print("serv: recvd %dB from internet\n", recvd);

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

      struct tun_rec *rec = NULL;
      int sport           = ntohs(((struct sockaddr_in *)nrec->sa6)->sin_port);
      int sent            = 0;
      if ( (rec = g_hash_table_lookup(state->serv, &sport)) ) {
         sent = xwrite(fd_tun, buf, recvd);
         debug_print("serv: wrote %dB to tun\n", sent); 
      } 
#if !defined(LOCKED)
      else if (g_hash_table_size(state->serv) <= state->fd_lim) { 
         sent = xwrite(fd_tun, buf, recvd);

         /* add new record to lookup tables */
         nrec->sport = sport;
         g_hash_table_insert(state->serv, &nrec->sport, nrec);
         debug_print("serv: added new entry: %d\n", sport);
      } 
#endif
      else {
         debug_print("dropping unknown UDP dgram (NAT ?)\n");
      }
          
   } else if (recvd < 0) {
       /* recvd ICMP msg */
      xrecverr(fd_net, buf,  BUFF_SIZE, 0, NULL);
   } else {
      /* recvd unknown packet */
      debug_print("serv: recvd empty pkt\n");
   }
   free_tun_rec(nrec);
}

void tun_serv_single(struct arguments *args) {
   int fd_net = 0, fd_tun = 0;
   void (*tun_serv_in_func)(int,int,struct tun_state*,char*);
   void (*tun_serv_out)(int,int,struct tun_state*,char*);

   /* init server state */
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */
   tun(state, &fd_tun); 
   if (state->ipv6) {
      if (state->udp)
         fd_net = udp_sock6(state->public_port, 1, state->public_addr6);
      else
         fd_net = raw_sock6(state->public_port, state->public_addr6, 
                            gen_bpf(state->default_if, state->public_addr6, 
                                    state->public_port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
      tun_serv_in_func = &tun_serv_in6;
      tun_serv_out     = &tun_serv_out6;
   } else {
      if (state->udp)
         fd_net = udp_sock4(state->public_port, 1, state->public_addr4);
      else
         fd_net = raw_sock4(state->public_port, state->public_addr4, 
                            gen_bpf(state->default_if, state->public_addr4, 
                                    state->public_port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
      tun_serv_in_func = &tun_serv_in4;
      tun_serv_out     = &tun_serv_out4;
   }

   /* run capture threads */
   xthread_create(capture_notun, (void *) state, 1);
   synchronize();

   /* run server */
   debug_print("running serv ...\n");  
   xthread_create(serv_thread, (void*) state, 1);

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

   fd_max=max(fd_tun,fd_net);
   loop=1;
   signal(SIGINT, serv_shutdown);
   signal(SIGTERM, serv_shutdown);

   while (loop) {
      FD_ZERO(&input_set);
      FD_SET(fd_net, &input_set);
      FD_SET(fd_tun, &input_set);
  
      sel = xselect(&input_set, fd_max, &tv, state->inactivity_timeout);

      if (sel == 0) {
         debug_print("timeout\n"); 
         break;
      } else if (sel > 0) {
         if (FD_ISSET(fd_net, &input_set)) 
            (*tun_serv_out)(fd_net, fd_tun, state, outbuffer);
         if (FD_ISSET(fd_tun, &input_set)) 
            (*tun_serv_in_func)(fd_net, fd_tun, state, inbuffer);
      }
   }
}

void tun_serv_dual(struct arguments *args) {
   int fd_net4 = 0, fd_net6 = 0, fd_tun = 0;

   /* init server state */
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */
   tun(state, &fd_tun); 
   if (state->udp) {
      fd_net4 = udp_sock4(state->public_port, 1, state->public_addr4);
      fd_net6 = udp_sock6(state->public_port, 1, state->public_addr6);
   } else {
      fd_net4 = raw_sock4(state->public_port, state->public_addr4, 
                         gen_bpf(state->default_if, state->public_addr4, 
                                 state->public_port, 0), 
                         state->default_if, state->protocol_num, 
                         1, state->planetlab);
      fd_net6 = raw_sock6(state->public_port, state->public_addr6, 
                         gen_bpf(state->default_if, state->public_addr6, 
                                 state->public_port, 0), 
                         state->default_if, state->protocol_num, 
                         1, state->planetlab);
   }

   /* run capture threads */
   xthread_create(capture_notun, (void *) state, 1);
   synchronize();

   /* run server */
   debug_print("running serv ...\n");  
   xthread_create(serv_thread, (void*) state, 1);

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

   fd_max=max(fd_tun,max(fd_net4, fd_net6));
   loop=1;
   signal(SIGINT, serv_shutdown);
   signal(SIGTERM, serv_shutdown);

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
         if (FD_ISSET(fd_net4, &input_set)) 
            tun_serv_out4(fd_net4, fd_tun, state, outbuffer);
         if (FD_ISSET(fd_net6, &input_set)) 
            tun_serv_out6(fd_net6, fd_tun, state, outbuffer);
         if (FD_ISSET(fd_tun, &input_set)) 
            tun_serv_in(fd_tun, fd_net4, fd_net6, state, inbuffer);
      }
   }
}


