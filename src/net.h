/**
 * \file net.h
 * \brief Prototypes of networking functions to be used 
 *    in cli, serv and peer mode.
 *
 * \author k.edeline
 * \version 0.1
 */

#ifndef UDPTUN_NET_H
#define UDPTUN_NET_H

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
 * \fn void *cli_thread(void *st);
 * \brief the TCP cli thread
 *
 * \param st udptun state
 * \return exit status
 */ 
void *cli_thread(void *st);

/**
 * \fn void *serv_thread(void *st);
 * \brief the TCP serv thread
 *
 * \param st udptun state
 * \return exit status
 */
void *serv_thread(void *st);

#endif

