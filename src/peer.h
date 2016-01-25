/**
 * \file peer.h
 * \brief This contains the argument structures and macros.
 * \author k.edeline
 * \version 0.1
 */

#ifndef UDPTUN_PEER_H
#define UDPTUN_PEER_H

#include "udptun.h"

/**
 * \fn void tun_peer(struct arguments *args)
 * \brief Runs a fullmesh peer.
 *
 * \param args A pointer to the server arguments. 
 * \return 
 */ 
void tun_peer(struct arguments *args);

#endif

