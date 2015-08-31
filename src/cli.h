/**
 * \file cli.h
 * \brief Functions prototypes for the client.
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_CLI_H
#define _UDPTUN_CLI_H

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
 * \fn void tun_cli(struct arguments *args)
 * \brief Runs the client.
 *
 * \param args A pointer to the client arguments.
 */ 
void tun_cli(struct arguments *args);

#endif
