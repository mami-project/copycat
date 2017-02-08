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
 * \fn static void tun_serv_in4(int fd_udp, int fd_tun, struct tun_state *state, char *buf)
 * \brief Forward a packet in the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_peer_in4(int fd_tun, int fd_cli, int fd_serv, 
                         struct tun_state *state, char *buf);
static void tun_peer_in6(int fd_tun, int fd_cli, int fd_serv, 
                         struct tun_state *state, char *buf);
static void tun_peer_in4_aux(int fd_cli, int fd_serv, 
                             struct tun_state *state, char *buf, int recvd);
static void tun_peer_in6_aux(int fd_cli, int fd_serv, 
                             struct tun_state *state, char *buf, int recvd);
static void tun_peer_in(int fd_tun, int fd_cli4, int fd_serv4, 
                 int fd_cli6, int fd_serv6, 
                 struct tun_state *state, char *buf);

/**
 * \fn static void tun_peer_out_cli4(int fd_udp, int fd_tun, struct tun_state *state, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_peer_out_cli4(int fd_udp, int fd_tun, struct tun_state *state, char *buf);
static void tun_peer_out_cli6(int fd_udp, int fd_tun, struct tun_state *state, char *buf);

/**
 * \fn static void tun_serv_out4(int fd_udp, int fd_tun, struct tun_state *state, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param state The state of the server.
 * \param buf The buffer.
 */ 
static void tun_peer_out_serv4(int fd_udp, int fd_tun, 
                               struct tun_state *state, char *buf);
static void tun_peer_out_serv6(int fd_udp, int fd_tun, 
                               struct tun_state *state, char *buf);

static void tun_peer_single(struct arguments *args);
static void tun_peer_dual(struct arguments *args);

void peer_shutdown(int UNUSED(sig)) { 
   debug_print("shutting down peer ...\n");

   /* Wait for delayed acks to avoid sending icmp */
   sleep(CLOSE_TIMEOUT);
   loop = 0; 
}

void tun_peer(struct arguments *args) {
   if (args->dual_stack)
      tun_peer_dual(args);
   else
      tun_peer_single(args);
}

void tun_peer_in(int fd_tun, int fd_cli4, int fd_serv4, 
                 int fd_cli6, int fd_serv6, 
                 struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("recvd %db from tun\n", recvd);

   switch (buf[0] & 0xf0) {
      case 0x40:
         tun_peer_in4_aux(fd_cli4, fd_serv4, state, buf, recvd);
         break;
      case 0x60:
         tun_peer_in6_aux(fd_cli6, fd_serv6, state, buf, recvd);
         break;
      default:
         debug_print("non-ip proto:%d\n", buf[0]);
         break;
   }
}

void tun_peer_in6(int fd_tun, int fd_cli, int fd_serv, 
                 struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("recvd %db from tun\n", recvd);
   tun_peer_in6_aux(fd_cli, fd_serv, state, buf, recvd);
}

void tun_peer_in4(int fd_tun, int fd_cli, int fd_serv, 
                 struct tun_state *state, char *buf) {
   int recvd=xread(fd_tun, buf, BUFF_SIZE);
   debug_print("recvd %db from tun\n", recvd);
   tun_peer_in4_aux(fd_cli, fd_serv, state, buf, recvd);
}

void tun_peer_in4_aux(int fd_cli, int fd_serv, 
                 struct tun_state *state, char *buf, int recvd) {
   if (recvd > MIN_PKT_SIZE) {

      /* Remove PlanetLab TUN PPI header */
      if (state->planetlab) {
         recvd-=4;
         memmove(buf, buf+4, recvd);
      }

      struct tun_rec *rec = NULL; 
      /* read sport for clients mapping */
      int dport = (int)ntohs( *((uint16_t *)(buf+22)) );

      /* cli */
      if (dport == state->private_port) {

         /* lookup initial server database from file */
         in_addr_t priv_addr = (int)*((uint32_t *)(buf+16));
         debug_print("%s\n", inet_ntoa((struct in_addr){priv_addr}));

         /* lookup private addr */
         if ( (rec = g_hash_table_lookup(state->cli4, &priv_addr)) ) {
            debug_print("priv addr lookup: OK\n");

            /* Add layer 4.5 header */
            if (state->raw_header) {
               buf -= state->raw_header_size;
               recvd += state->raw_header_size;
            }

            int sent = xsendto4(fd_cli, rec->sa4, buf, recvd);
            debug_print("wrote %db to internet\n",sent);

         } else {
            errno=EFAULT;
            die("cli lookup");
         }

      /* serv */
      } else if ((rec = g_hash_table_lookup(state->serv, &dport))) {   

         /* Add layer 4.5 header */
         if (state->raw_header) {
            buf -= state->raw_header_size;
            recvd += state->raw_header_size;
         }

         int sent = xsendto4(fd_serv, rec->sa4, buf, recvd);
         debug_print("wrote %db to internet\n",sent);
      } else {
         debug_print("serv lookup failed proto:%d sport:%d dport:%d\n", 
                      (int) *((uint8_t *)(buf+9)), 
                      (int) ntohs( *((uint16_t *)(buf+20)) ), 
                      dport);
      }
   } 
}

void tun_peer_in6_aux(int fd_cli, int fd_serv, 
                      struct tun_state *state, char *buf, int recvd) {
   if (recvd > MIN_PKT_SIZE) {

      /* Remove PlanetLab TUN PPI header */
      if (state->planetlab) {
         recvd-=4;
         memmove(buf, buf+4, recvd);
      }

      struct tun_rec *rec = NULL; 
      /* read sport for clients mapping */
      int dport = (int)ntohs( *((uint16_t *)(buf+42)) );

      /* cli */
      if (dport == state->private_port) { 

         /* lookup initial server database from file */
         char priv_addr6[16], str_addr6[INET6_ADDRSTRLEN];
         memcpy(priv_addr6, buf+24, 16);
         debug_print("%s\n", inet_ntop(AF_INET6, priv_addr6, 
                               str_addr6, INET6_ADDRSTRLEN));
         
         /* lookup private addr */
         if ( (rec = g_hash_table_lookup(state->cli6, priv_addr6)) ) {
            debug_print("priv addr lookup: OK\n");

            /* Add layer 4.5 header */
            if (state->raw_header) {
               buf -= state->raw_header_size;
               recvd += state->raw_header_size;
            }
            int sent = xsendto6(fd_cli, rec->sa6, buf, recvd);
            debug_print("wrote %db to internet\n",sent);
            if (sent <0) debug_perror();
         } else {
            errno=EFAULT;
            die("cli lookup");
         }

      /* serv */
      } else if ((rec = g_hash_table_lookup(state->serv, &dport))) {   

         /* Add layer 4.5 header */
         if (state->raw_header) {
            buf -= state->raw_header_size;
            recvd += state->raw_header_size;
         }

         int sent = xsendto6(fd_serv, rec->sa6, buf, recvd);
         debug_print("wrote %db to internet\n",sent);
      } else {
         debug_print("serv lookup failed proto:%d sport:%d dport:%d\n", 
                      (int) *((uint8_t *)(buf+6)), 
                      (int) ntohs( *((uint16_t *)(buf+40)) ), 
                      dport);
      }
   } 
}

void tun_peer_out_cli4(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {
   int recvd = xrecv(fd_udp, buf, BUFF_SIZE);

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
      xrecverr(fd_udp, buf, BUFF_SIZE, 0, NULL);
   } else {
      /* recvd unknown packet */
      debug_print("cli: recvd empty pkt\n");
   }   
}

void tun_peer_out_cli6(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {
   int recvd = xrecv(fd_udp, buf, BUFF_SIZE);

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
      xrecverr(fd_udp, buf, BUFF_SIZE, 0, NULL);
   } else {
      /* recvd unknown packet */
      debug_print("cli: recvd empty pkt\n");
   }   
}

void tun_peer_out_serv4(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {
   struct tun_rec *nrec = init_tun_rec(state);
   int recvd = xrecvfrom(fd_udp, (struct sockaddr *)nrec->sa4, 
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
         debug_print("serv: wrote %dB to internet\n", sent); 
      } 
#if !defined(LOCKED)
      else if (g_hash_table_size(state->serv) <= state->fd_lim) { 
         
         sent = xwrite(fd_tun, buf, recvd);

         //add new record to lookup tables  
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
      xrecverr(fd_udp, buf,  BUFF_SIZE, 0, NULL);
   } else {
      /* recvd unknown packet */
      debug_print("serv: recvd empty pkt\n");
   }
   free_tun_rec(nrec);
}

void tun_peer_out_serv6(int fd_udp, int fd_tun, struct tun_state *state, char *buf) {
   struct tun_rec *nrec = init_tun_rec(state);
   int recvd = xrecvfrom(fd_udp, (struct sockaddr *)nrec->sa6, 
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
      xrecverr(fd_udp, buf,  BUFF_SIZE, 0, NULL);
   } else {
      /* recvd unknown packet */
      debug_print("serv: recvd empty pkt\n");
   }
   free_tun_rec(nrec);
}

void tun_peer_single(struct arguments *args) {
   int fd_tun = 0, fd_serv = 0, fd_cli = 0;
   void (*tun_peer_in_func)(int,int,int,struct tun_state*,char*);
   void (*tun_peer_out_cli)(int,int,struct tun_state*,char*);
   void (*tun_peer_out_serv)(int,int,struct tun_state*,char*);
   
   /* init state */ 
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */
   tun(state, &fd_tun);   
   if (state->ipv6) {
      if (state->udp) {
         fd_serv = udp_sock6(state->public_port, 1, state->public_addr6);
         fd_cli  = udp_sock6(state->port, 1, state->public_addr6);
      } else {
         fd_serv = raw_sock6(state->public_port, state->public_addr6, 
                            gen_bpf(state->default_if, state->public_addr6, 
                                    state->public_port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
         fd_cli  = raw_sock6(state->port, state->public_addr6, 
                            gen_bpf(state->default_if, state->public_addr6, 
                                    state->port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
      }
      tun_peer_out_cli = &tun_peer_out_cli6;
      tun_peer_out_serv = &tun_peer_out_serv6;
      tun_peer_in_func = &tun_peer_in6;
   } else {
      if (state->udp) {
         fd_serv = udp_sock4(state->public_port, 1, state->public_addr4);
         fd_cli  = udp_sock4(state->port, 1, state->public_addr4);
      } else {
         fd_serv = raw_sock4(state->public_port, state->public_addr4, 
                            gen_bpf(state->default_if, state->public_addr4, 
                                    state->public_port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
         fd_cli  = raw_sock4(state->port, state->public_addr4, 
                            gen_bpf(state->default_if, state->public_addr4, 
                                    state->port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
      }

      tun_peer_out_cli = &tun_peer_out_cli4;
      tun_peer_out_serv = &tun_peer_out_serv4;
      tun_peer_in_func = &tun_peer_in4;
   }

   /* run capture threads */
   xthread_create(capture_notun, (void *) state, 1);
   synchronize();

   /* run server */
   debug_print("running serv ...\n");  
   xthread_create(serv_thread, (void*) state, 1);

   /* run client */
   debug_print("running cli ...\n"); 
   xthread_create(cli_thread, (void*) state, 1);

   /* init select main loop */
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

   fd_max = max(max(fd_cli, fd_tun), fd_serv);
   loop   = 1;
   signal(SIGINT,  peer_shutdown);
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
            (*tun_peer_in_func)(fd_tun, fd_cli, fd_serv, state, inbuffer); 
         if (FD_ISSET(fd_cli, &input_set)) 
            (*tun_peer_out_cli)(fd_cli, fd_tun, state, outbuffer);
         if (FD_ISSET(fd_serv, &input_set)) 
            (*tun_peer_out_serv)(fd_serv, fd_tun, state, outbuffer);
      }
   }
}

void tun_peer_dual(struct arguments *args) {
   int fd_tun = 0, fd_serv4 = 0, fd_cli4 = 0, fd_serv6 = 0, fd_cli6 = 0;

   /* init state */ 
   struct tun_state *state = init_tun_state(args);

   /* create tun if and sockets */
   tun(state, &fd_tun);   
   if (state->udp) {
      fd_serv4 = udp_sock4(state->public_port, 1, state->public_addr4);
      fd_cli4  = udp_sock4(state->port, 1, state->public_addr4);
      fd_serv6 = udp_sock6(state->public_port, 1, state->public_addr6);
      fd_cli6  = udp_sock6(state->port, 1, state->public_addr6);
   } else {
      fd_serv4 = raw_sock4(state->public_port, state->public_addr4, 
                            gen_bpf(state->default_if, state->public_addr4, 
                                    state->public_port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
      fd_cli4  = raw_sock4(state->port, state->public_addr4, 
                            gen_bpf(state->default_if, state->public_addr4, 
                                    state->port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
      fd_serv6 = raw_sock6(state->public_port, state->public_addr6, 
                            gen_bpf(state->default_if, state->public_addr6, 
                                    state->public_port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
      fd_cli6  = raw_sock6(state->port, state->public_addr6, 
                            gen_bpf(state->default_if, state->public_addr6, 
                                    state->port, 0), 
                            state->default_if, state->protocol_num, 
                            1, state->planetlab);
   }

   /* run capture threads */
   xthread_create(capture_notun, (void *) state, 1);
   synchronize();

   /* run server */
   debug_print("running serv ...\n");  
   xthread_create(serv_thread, (void*) state, 1);

   /* run client */
   debug_print("running cli ...\n"); 
   xthread_create(cli_thread, (void*) state, 1);

   /* init select main loop */
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

   fd_max = max(max(max(max(fd_cli4, fd_tun), fd_serv4), fd_cli6), fd_serv6);
   loop   = 1;
   signal(SIGINT,  peer_shutdown);
   signal(SIGTERM, peer_shutdown);

   while (loop) {
      FD_ZERO(&input_set);
      FD_SET(fd_tun,  &input_set);
      FD_SET(fd_cli4,  &input_set);
      FD_SET(fd_serv4, &input_set);
      FD_SET(fd_cli6,  &input_set);
      FD_SET(fd_serv6, &input_set);

      sel = xselect(&input_set, fd_max, &tv, state->inactivity_timeout);

      if (sel == 0) {
         debug_print("timeout\n"); 
         break;
      } else if (sel > 0) {
         if (FD_ISSET(fd_cli4, &input_set)) 
            tun_peer_out_cli4(fd_cli4, fd_tun, state, outbuffer);
         if (FD_ISSET(fd_cli6, &input_set)) 
            tun_peer_out_cli6(fd_cli6, fd_tun, state, outbuffer);
         if (FD_ISSET(fd_tun, &input_set))      
            tun_peer_in(fd_tun, fd_cli4, fd_serv4, fd_cli6, fd_serv6, 
                        state, inbuffer); 
         if (FD_ISSET(fd_serv4, &input_set)) 
            tun_peer_out_serv4(fd_serv4, fd_tun, state, outbuffer);
         if (FD_ISSET(fd_serv6, &input_set)) 
            tun_peer_out_serv6(fd_serv6, fd_tun, state, outbuffer);
      }
   }
}

