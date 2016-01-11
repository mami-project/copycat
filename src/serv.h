/**
 * \file serv.h
 *    \brief Functions prototypes for the server.
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_SERV_H
#define _UDPTUN_SERV_H

#include "udptun.h"

/**
 * \fn void tun_serv(struct arguments *args)
 * \brief Runs the server.
 *
 * \param args A pointer to the server arguments. 
 * \return 
 */ 
void tun_serv(struct arguments *args);

#endif

