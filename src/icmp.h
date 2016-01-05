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

#include "debug.h"

/*
 * ICMP_ECHO/ICMP_ECHO_REPLY prototype
 */
struct icmp_msg
{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	char data[8]; 
};

/*
 * IP_HEADER prototype
 */
struct ip_header
{
	unsigned int	hl:4,		/* 4 bit header length */
					ver:4;		/* 4 bit version */
	unsigned char	tos;		/* type of service */
	unsigned short  totl;		/* total length of datagram */
	unsigned short	id;		/* identifier */
	unsigned short 	notused;	/* this is were flags and fragment offset would go */
	unsigned char 	ttl;		/* time to live */
	unsigned char	prot;		/* protocol */
	unsigned short	csum;		/* our checksum */
	uint32_t 	saddr;		/* source address */
	uint32_t 	daddr;		/* destination address */
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

