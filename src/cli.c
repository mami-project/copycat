/*
 * cli.c: client
 * 
 *
 * @author k.edeline
 */

#include "cli.h"

void tun_cli(struct arguments *args) {
   /*
    * ./udptun -c --udp-daddr=109.89.113.79 --udp-dport=9876 --udp-sport=5001 --tcp-laddr=192.168.2.1 --tcp-lport=9877 --tcp-ndport=9876
    * TODO: bind tcp-connect to tun otherwise kernel will answer
    */
   //open udp sendto
   const char *prefix="24";
   char content[__BUFFSIZE], content2[__BUFFSIZE];

   char *if_name=create_tun(args->tcp_laddr, prefix, 0);
   int fd_udp=udp_sock(args->udp_sport);

   int fd_raw=raw_tcp_sock(args->tcp_laddr, args->tcp_lport, if_name);//TODO: add filter for 

   struct sockaddr_in *udp_addr = get_addr(args->udp_daddr, args->udp_dport);

   //xsendto(fd_udp, udp_addr, content, strlen(content));

   //open raw recv
   int recv_s =0;
   //struct sockaddr_in *tcp_addr = get_addr(NULL, args->tcp_lport); TODO:filter raw socket by port
   //int addrlen=sizeof(struct sockaddr);
   while (1) {
      recv_s=xrecv(fd_raw, content, sizeof(content));

      printf ("SIZE:%d\n", recv_s);
      for (int i=0;i<recv_s;i++) {
         printf("%x ",content[i]);
         if (!((i+1)%16)) printf("\n"); 
      }
      printf("\n");  
      sleep(1);
      xsendto(fd_udp, udp_addr, content, recv_s);
   }

   free(if_name);
   return;
}
