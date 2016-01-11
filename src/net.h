/**
 * \file net.h
 * \brief Prototypes of networking functions to be used 
 *    in cli, serv and peer mode.
 *
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_NET_H
#define _UDPTUN_NET_H

#include <netinet/in.h>

#include "state.h"

/**
 * \fn struct sockaddr_in *get_addr(const char *addr, int port)
 * \brief Allocate an AF_INET socket address structure.
 *
 * \param addr The sockaddr address.
 * \param port The sockaddr port.
 * \return A pointer (malloc) to the created struct sockaddr_in
 */ 
struct sockaddr_in *get_addr(const char *addr, int port);

/**
 * \fn int tcp_serv(char *addr, int port, char *filename)
 * \brief connect a TCP socket to addr:port and write
 * received data to filename.
 *
 * \param addr The remote address to connect to.
 * \param port The remote port to connect to.
 * \param filename The file to write to.
 * \return exit status
 */ 

void *cli_thread(void *state); //TODO move inside module

void *serv_thread(void *state);

int tcp_serv(char *daddr, int dport, char* dev, struct tun_state *state);

#endif
