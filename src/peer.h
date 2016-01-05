/**
 * \file peer.h
 * \brief This contains the argument structures and macros.
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_PEER_H
#define _UDPTUN_PEER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <glib.h>

#include "debug.h"
#include "udptun.h"
#include "sock.h"
#include "serv.h"
#include "tunalloc.h"

/**
 * \fn void tun_peer(struct arguments *args)
 * \brief Runs a fullmesh peer.
 *
 * \param args A pointer to the server arguments. 
 * \return 
 */ 
void tun_peer(struct arguments *args);

#endif

