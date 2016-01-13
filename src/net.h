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
 * \fn void tun(struct tun_state *state, int *fd_tun);
 * \brief Allocate an AF_INET socket address structure.
 *
 * \param state udptun state
 * \param fd_tun a pointer to the memory where the tun fd will
 *               be written
 */ 
void tun(struct tun_state *state, int *fd_tun);

/**
 * \fn void *cli_thread(void *state);
 * \brief the TCP cli thread
 *
 * \param state udptun state
 * \return exit status
 */ 
void *cli_thread(void *state);

/**
 * \fn void *serv_thread(void *state);
 * \brief the TCP serv thread
 *
 * \param state udptun state
 * \return exit status
 */
void *serv_thread(void *state);

/**
 * \fn struct sockaddr_in *get_addr(const char *addr, int port)
 * \brief Allocate an AF_INET socket address structure.
 *
 * \param addr The sockaddr address.
 * \param port The sockaddr port.
 * \return A pointer (malloc) to the created struct sockaddr_in
 */ 
struct sockaddr_in *get_addr(const char *addr, int port);

#endif
