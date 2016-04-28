/**
 * \file icmp.h
 *    \brief Functions prototypes for ICMP handling.
 * \author k.edeline
 * \version 0.1
 */

#ifndef UDPTUN_ICMP_H
#define UDPTUN_ICMP_H

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/uio.h>

#include "state.h"

#  if defined(LINUX_OS)
/**
 * \fn void print_icmp_type(uint8_t type, uint8_t code)
 * \brief print (via debug_print macro) the icmp msg type
 *
 * \param type The icmp msg type
 * \param code The icmp msg code
 */ 
void print_icmp_type(uint8_t type, uint8_t code);

/**
 * \fn char *forge_icmp(int *pkt_len, struct sock_extended_err *sock_err,
 *                struct iovec *iov, struct tun_state *state)
 * \brief a dirty function that re-forge an icmp msg from
 *          iovec and sock_extended_err and returns it.
 *
 * \param pkt_len
 * \param sock_err
 * \param iov
 * \param state The program state
 * \return The packet
 */ 
char *forge_icmp(int *pkt_len, struct sock_extended_err *sock_err,
                 struct iovec *iov, struct tun_state *state);
#  endif

#endif

