/**
 * \file icmp.c
 * \brief ICMP handling implementation.
 * \author k.edeline
 * \version 0.1
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sysconfig.h"
#if defined(BSD_OS)
//there is no BSD errqueue :'(
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#elif defined(LINUX_OS)
#include <linux/errqueue.h>
#endif
#include <sys/socket.h>
#include <arpa/inet.h>

#include "icmp.h"
#include "debug.h"

/** 
 * \struct icmp_msg
 *	\brief An icmp msg
 */
struct icmp_msg {
	unsigned char type;      /*!< msg type  */
	unsigned char code;      /*!< msg code   */
	unsigned short checksum; /*!< msh checksum */
	char data[8];            /*!< msg payload */
};

/** 
 * \struct ip_header
 *	\brief an ip header
 */
struct ip_header {
	unsigned int	hl:4,		/*!< 4 bit header length */
					ver:4;		/*!< 4 bit version */
	unsigned char	tos;		/*!< type of service */
	unsigned short  totl;		/*!< total length of datagram */
	unsigned short	id;	   	/*!< identifier */
	unsigned short 	notused;	/*!< this is were flags and fragment offset would go */
	unsigned char 	ttl;		   /*!< time to live */
	unsigned char	prot;		   /*!< protocol */
	unsigned short	csum;		   /*!< our checksum */
	uint32_t 	saddr;		   /*!< source address */
	uint32_t 	daddr;		   /*!< destination address */
};

/**
 * \fn unsigned short calcsum(unsigned short *buffer, int length)
 *
 * \brief used to calculate IP and ICMP header checksums using
 * one's compliment of the one's compliment sum of 16 bit words of the header
 * 
 * \param buffer the packet buffer
 * \param length the buffer length
 * \return checksum
 */ 
static unsigned short calcsum(unsigned short *buffer, int length);

#if defined(LINUX_OS)

void print_icmp_type(uint8_t type, uint8_t code) {

   /* icmp msg types */
   switch (type) {
      case ICMP_DEST_UNREACH:
         /* icmp type 3 codes */
         switch (code) {
            case ICMP_NET_UNREACH:
               debug_print("icmp network unreachable\n");
               break;
            case ICMP_HOST_UNREACH:
               debug_print("icmp host unreachable\n");
               break;
            case ICMP_PROT_UNREACH:
               debug_print("icmp protocol unreachable\n");
               break;
            case ICMP_PORT_UNREACH:
               debug_print("icmp port unreachable\n");
               break;
            default:
               debug_print("icmp unreachable code %d\n", code);
               break;
         }
         break;
      case ICMP_SOURCE_QUENCH:
         debug_print("icmp source quench\n");
         break;
      case ICMP_REDIRECT:
         debug_print("icmp redirect\n");
         break;
      case ICMP_TIME_EXCEEDED:
         debug_print("icmp time exceeded\n");
         break;
      case ICMP_PARAMETERPROB:
         debug_print("icmp parameter problem\n");
         break;
      default:
         debug_print("icmp type %d code %d\n", type, code);
         break;
   }
}

char *forge_icmp(int *pkt_len, struct sock_extended_err *sock_err, struct iovec *iov, struct tun_state *state) {
   /* re-build icmp msg */
   struct ip_header* ipheader;
   struct icmp_msg* icmp;
   struct sockaddr *sa = SO_EE_OFFENDER(sock_err);
   debug_print("%s\n", inet_ntoa(((struct sockaddr_in *)sa)->sin_addr));

   char *pkt;
   *pkt_len = sizeof(struct ip_header) + sizeof(struct icmp_msg);
   if ( (pkt = calloc(1, *pkt_len)) == NULL) {
      *pkt_len=0;
      return NULL;
   }
   ipheader = (struct ip_header*)pkt;
   icmp = (struct icmp_msg*)(pkt+sizeof(struct ip_header));

   /* fill packet */
   ipheader->ver 		= 4; 
   ipheader->hl		= 5; 	
   ipheader->tos		= 0;
   ipheader->totl		= *pkt_len;
   ipheader->id		= 0;
   ipheader->notused	= 0;	
   ipheader->ttl		= 255;  
   ipheader->prot		= 1;	
   ipheader->csum		= 0;
   ipheader->saddr 	= ((struct sockaddr_in *)sa)->sin_addr.s_addr;
   ipheader->daddr   = (unsigned long)inet_addr(state->private_addr);
   icmp->type		   = sock_err->ee_type;		
   icmp->code		   = sock_err->ee_code;		
   icmp->checksum    = 0;
   int i;
   for (i=0; i<8; i++)          
      icmp->data[i]  = ((unsigned char *) iov->iov_base)[i];
   icmp->checksum    = calcsum((unsigned short*)icmp, 
                               sizeof(struct icmp_msg));
   ipheader->csum		= calcsum((unsigned short*)ipheader, 
                               sizeof(struct ip_header));
   
   return pkt;
}
#endif

unsigned short calcsum(unsigned short *buffer, int length) {
	unsigned long sum; 	
	for (sum=0; length>1; length-=2) 
		sum += *buffer++;	

	if (length==1)
		sum += (char)*buffer;

	sum = (sum >> 16) + (sum & 0xFFFF); 
	sum += (sum >> 16);		   
	return ~sum;
}

