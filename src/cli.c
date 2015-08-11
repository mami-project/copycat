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
static void tun_cli_out(int fd_udp, int fd_raw, struct sockaddr_in *tcp_addr, char *buf);

void int_handler(int sig) { loop = 0; }

void tun_cli_in(int fd_udp, int fd_raw, struct sockaddr_in *udp_addr, char *buf) {


      int recv_s=xrecv(fd_raw, buf, __BUFFSIZE);

      //todo change dport to args->ndport
      printf ("recvd %db from raw\n", recv_s);
      for (int i=0;i<recv_s;i++) {
         printf("%x ",buf[i]);
         if (!((i+1)%16)) printf("\n"); 
      }
      printf("\n"); 
 
      if (recv_s > 0) xsendto(fd_udp, udp_addr, buf, recv_s);
}

void tun_cli_out(int fd_udp, int fd_raw, struct sockaddr_in *tcp_addr, char *buf) {

      int recv_s=xrecv(fd_udp, buf, __BUFFSIZE);

      //todo change dport to args->ndport
      printf ("recvd %db from udp\n", recv_s);
      for (int i=0;i<recv_s;i++) {
         printf("%x ",buf[i]);
         if (!((i+1)%16)) printf("\n"); 
      }
      printf("\n");  

      if (recv_s > 0) xsendto(fd_raw, tcp_addr, buf, recv_s);
}

void tun_cli(struct arguments *args) {
   /*
    * udptun -c --udp-daddr=132.227.62.120 --udp-sport=34501 --udp-dport=5001 --tcp-saddr=192.168.2.1 --tcp-sport=34500 --tcp-dport=9877 --tcp-ndport=9876
    */
   int fd_max = 0, fd_udp = 0, fd_raw = 0, sel = 0;
   char *if_name = NULL;
   struct sockaddr_in *udp_addr = NULL, *tcp_addr = NULL;
   struct sock_fprog *bpf = NULL;

   //init tun itf
   const char *prefix = "24";
   if_name  = create_tun(args->tcp_saddr, prefix, 0);
   //udp sock & dst sockaddr
   fd_udp   = udp_sock(args->udp_sport);
   udp_addr = get_addr(args->udp_daddr, args->udp_dport);
   //raw tcp sock with tcp dport bpf
   bpf      = gen_bpf(if_name, args->tcp_saddr, 0, args->tcp_dport);
   //raw sock & dst sockaddr
   fd_raw   = raw_tcp_sock(args->tcp_saddr, args->tcp_dport, bpf);
   tcp_addr = get_addr(args->tcp_saddr, args->tcp_sport);

   loop = 1;
   signal(SIGINT, int_handler);

   fd_set input_set;//, output_set;
   fd_max = max(fd_udp, fd_raw);
   struct timeval tv;
   char buf[__BUFFSIZE];

   while (loop) {
      //select list
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);
      FD_SET(fd_raw, &input_set);
      //FD_ZERO(&output_set);  TODO
      //FD_SET(fd_udp, &output_set);
      //FD_SET(fd_raw, &output_set);
      tv.tv_sec  = 1;
      tv.tv_usec = 0;

      sel = select(fd_max+1, &input_set, NULL, NULL, &tv);
      if (sel < 0) die("select");
      else if (sel > 0) {
         if (FD_ISSET(fd_raw, &input_set))      
            tun_cli_in(fd_udp, fd_raw, udp_addr, buf);
         if (FD_ISSET(fd_udp, &input_set)) 
            tun_cli_out(fd_udp, fd_raw, tcp_addr, buf);
      }
   }

   close(fd_udp);close(fd_raw);
   free(if_name);free((struct bpf_program *)bpf);

   return;
}
