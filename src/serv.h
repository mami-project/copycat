/**
 * \file serv.h
 *    \brief Functions prototypes for the server.
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_SERV_H
#define _UDPTUN_SERV_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "debug.h"
#include "udptun.h"
#include "sock.h"

/**
 * \fn void tun_serv(struct arguments *args)
 * \brief Runs the server.
 *
 * \param args A pointer to the server arguments. 
 * \return 
 */ 
void tun_serv(struct arguments *args);

#endif

