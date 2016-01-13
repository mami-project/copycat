/**
 * \file icmp.h
 *    \brief Functions prototypes for ICMP handling.
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_ICMP_H
#define _UDPTUN_ICMP_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>

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
 * \fn void print_icmp_type((uint8_t type, uint8_t code)
 * \brief print (via debug_print macro) the icmp msg type
 *
 * \param type The icmp msg type
 * \param code The icmp msg code
 */ 
void print_icmp_type(uint8_t type, uint8_t code);

#endif

