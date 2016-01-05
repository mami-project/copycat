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
static void tun_cli_in(int fd_udp, int fd_tun, struct sockaddr_in *udp_addr, char *buf);

/**
 * \fn static void tun_cli_out(int fd_udp, int fd_tun, char *buf)
 * \brief Forward a packet out of the tunnel.
 *
 * \param fd_udp The udp socket fd.
 * \param fd_tun The tun interface fd.
 * \param buf The buffer. 
 */ 
static void tun_cli_out(int fd_udp, int fd_tun, char *buf);

static void tun_cli_aux(struct arguments *args);
static void tun_cli_pl(struct arguments *args);
static void tun_cli_fbsd(struct arguments *args);

void cli_shutdown(int sig) { 
   debug_print("shutting down client ...\n");

   /* Wait for delayed acks to avoid sending icmp */
   sleep(__CLOSE_TIMEOUT);

   loop = 0; 
}

void tun_cli_in(int fd_udp, int fd_tun, struct sockaddr_in *udp_addr, char *buf) {

      int recvd=xread(fd_tun, buf, __BUFFSIZE);
      debug_print("cli: recvd %db from tun\n", recvd);

      if (recvd > 0) { 
         int sent = xsendto(fd_udp, (struct sockaddr *)udp_addr, buf, recvd);
         debug_print("cli: wrote %db to udp\n",sent);
      }
}

void tun_cli_out(int fd_udp, int fd_tun, char *buf) {
      int recvd=xrecv(fd_udp, buf, __BUFFSIZE);
      debug_print("cli: recvd %db from udp\n", recvd);

      if (recvd > 0) { 
         int sent = xwrite(fd_tun, buf, recvd);
         debug_print("cli: wrote %db to tun\n",sent);
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
   /* e.g.
    * udptun -c --udp-daddr=132.227.62.120 --udp-sport=34501 --udp-dport=5001 --tcp-saddr=192.168.2.1 --tcp-sport=34500 --tcp-dport=9877 --tcp-daddr=132.227.62.121

    ./src/udptun -c --udp-daddr=139.165.223.57 --udp-sport=34501 --udp-dport=5001 --tcp-saddr=192.168.2.2 --tcp-sport=34501 --tcp-dport=9876 --tcp-daddr=192.168.2.1
    */
   int fd_tun = 0, fd_udp = 0, fd_tcp = 0;
   int fd_max = 0, sel = 0;
   struct sockaddr_in *udp_addr = NULL, *tcp_addr = NULL;
   
   // init tun0 interface
   struct tun_state *state = init_tun_state(args);
   args->if_name  = create_tun(args->tcp_saddr, NULL, &fd_tun);   
   fd_udp   = udp_sock(args->udp_sport);
   udp_addr = get_addr(args->udp_daddr, args->udp_dport);

   //run cli worker thread
   pthread_t thread_id;
   if (pthread_create(&thread_id, NULL, cli_thread, (void*) args) < 0) 
      die("pthread_create");

   // set atexit
   set_pthread(thread_id);

   fd_set input_set;
   struct timeval tv;
   char buf[__BUFFSIZE];
   fd_max = max(fd_udp, fd_tun);

   loop = 1;
   signal(SIGINT, cli_shutdown);

   while (loop) {
      //build select list
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);
      FD_SET(fd_tun, &input_set);

      tv.tv_sec  = state->inactivity_timeout; 
      tv.tv_usec = 0;

      sel = select(fd_max+1, &input_set, NULL, NULL, &tv);
      if (sel < 0) die("select");
      else if (sel == 0) {
         debug_print("timeout\n"); 
         break;
      } else if (sel > 0) {
         if (FD_ISSET(fd_tun, &input_set))      
            tun_cli_in(fd_udp, fd_tun, udp_addr, buf);
         if (FD_ISSET(fd_udp, &input_set)) 
            tun_cli_out(fd_udp, fd_tun, buf);
      }
   }

   close(fd_udp);
   free(args->if_name);free(udp_addr);
   
}

void tun_cli_fbsd(struct arguments *args) {
   // init tun itf
   int fd_tun     = 0;
   //char *if_name = create_tun(args->tcp_saddr,NULL, &fd_tun);

}

void tun_cli_pl(struct arguments *args) {
   int fd_max = 0, fd_udp = 0, fd_raw = 0, sel = 0;
   char *if_name = NULL;
   struct sockaddr_in *udp_addr = NULL, *tcp_addr = NULL;
   struct sock_fprog *bpf = NULL;

   //init tun itf
   const char *prefix = "24";
   int tun_fd = 0;
   struct tun_state *state = init_tun_state(args);
   if_name  = create_tun_pl(args->tcp_saddr, prefix, 0, &tun_fd);
   //udp sock & dst sockaddr

   fd_udp   = udp_sock(args->udp_sport);
   udp_addr = get_addr(args->udp_daddr, args->udp_dport);

   //run TCP cli
   /*
   pid_t child = fork();
   if (!child) {
      tcp_cli(args->tcp_daddr, args->tcp_dport, args->tcp_saddr, args->tcp_sport, if_name, "test.dat");
      return;
   } else if (child < 0) {
      die("fork");
   }*/

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
         if (FD_ISSET(tun_fd, &input_set))      
            tun_cli_in(fd_udp, tun_fd, udp_addr, buf);
         if (FD_ISSET(fd_udp, &input_set)) 
            tun_cli_out(fd_udp, tun_fd, buf);
      }
   }

   close(fd_udp);
   free(if_name);free(udp_addr);free((struct bpf_program *)bpf);
}

