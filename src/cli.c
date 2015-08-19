/*
 * cli.c: client
 * 
 *
 * @author k.edeline
 */

#include "cli.h"

static volatile int loop;

static void int_handler(int sig);
static void tun_cli_in(int fd_udp, int fd_raw, struct sockaddr_in *udp_addr, char *buf);
static void tun_cli_out(int fd_udp, int fd_raw, char *buf);

void int_handler(int sig) { loop = 0; }

void tun_cli_in(int fd_udp, int fd_tun, struct sockaddr_in *udp_addr, char *buf) {

      int recvd=xread(fd_tun, buf, __BUFFSIZE);
#ifdef __DEBUG
      //todo change dport to args->ndport
      fprintf (stderr,"cli: recvd %db from tun\n", recvd);
#endif

      if (recvd > 0) { 
         int sent = xsendto(fd_udp, (struct sockaddr *)udp_addr, buf, recvd);
#ifdef __DEBUG
         fprintf(stderr,"cli: wrote %db to udp\n",sent);
#endif
      }
}

void tun_cli_out(int fd_udp, int fd_tun, char *buf) {

      int recvd=xrecv(fd_udp, buf, __BUFFSIZE);
#ifdef __DEBUG
      //todo change dport to args->ndport
       fprintf (stderr,"cli: recvd %db from udp\n", recvd);
      if (recvd > 32) {
         fprintf(stderr,"ports %d %d\n",ntohs( *((uint16_t *)buf+24) ),
                                        ntohs( *((uint16_t *)buf+26) ));
      }
#endif

      if (recvd > 0) { 
         int sent = xwrite(fd_tun, buf, recvd);
#ifdef __DEBUG
         fprintf(stderr,"cli: wrote %db to tun\n",sent);
#endif
      }
}

void tun_cli(struct arguments *args) {
   /* e.g.
    * udptun -c --udp-daddr=132.227.62.120 --udp-sport=34501 --udp-dport=5001 --tcp-saddr=192.168.2.1 --tcp-sport=34500 --tcp-dport=9877 --tcp-ndport=9876
    */
   int fd_max = 0, fd_udp = 0, fd_raw = 0, sel = 0;
   char *if_name = NULL;
   struct sockaddr_in *udp_addr = NULL, *tcp_addr = NULL;
   struct sock_fprog *bpf = NULL;

   //init tun itf
   const char *prefix = "24";
   int tun_fd = 0;
   if_name  = create_tun(args->tcp_saddr, prefix, 0, &tun_fd);
   //udp sock & dst sockaddr
   fd_udp   = udp_sock(args->udp_sport);
   udp_addr = get_addr(args->udp_daddr, args->udp_dport);

   loop = 1;
   signal(SIGINT, int_handler);

   fd_set input_set;
   fd_max = max(fd_udp, tun_fd);
   struct timeval tv;
   char buf[__BUFFSIZE];

   while (loop) {
      //select list
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);FD_SET(tun_fd, &input_set);

      tv.tv_sec  = 1;
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
   free(if_name);free((struct bpf_program *)bpf);

   return;
}
