/*
 * serv.c: server
 * 
 *
 * @author k.edeline
 */

#include "serv.h"

void tun_serv(struct arguments *args) {
   //when new udp recvd, open send raw socket and select on them
   //
   struct sockaddr_in si_other;

   int s, recv_len, buflen = 1440;
   socklen_t slen = sizeof(si_other);
   char *buf = malloc(buflen);

   s=udp_sock(5001);
   //keep listening for data
   while(1)
   {
     printf("Waiting for data...");
     fflush(stdout);
      
     //try to receive some data, this is a blocking call
     if ((recv_len = recvfrom(s, buf, buflen, 0, (struct sockaddr *) &si_other, &slen)) == -1)
     {
         die("recvfrom()");
     }
      
     //print details of the client/peer and the data received
     printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
     printf("Data: %s\n" , buf);
      
     //now reply the client with the same data
     if (sendto(s, buf, recv_len, 0, (struct sockaddr*) &si_other, slen) == -1)
     {
         die("sendto()");
     }
   }

   close(s);
}
