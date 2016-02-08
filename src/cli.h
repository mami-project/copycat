/**
 * \file cli.h
 * \brief Functions prototypes for the client.
 * \author k.edeline
 * \version 0.1
 */

#ifndef UDPTUN_CLI_H
#define UDPTUN_CLI_H

#include "udptun.h"

/**
 * \fn void tun_cli(struct arguments *args)
 * \brief Runs the client.
 *
 * \param args A pointer to the client arguments.
 */ 
void tun_cli(struct arguments *args);

/**
 * \fn void cli_shutdown(int sig)
 * \brief Callback function for SIGINT catcher.
 *
 * \param sig Ignored
 */ 
void cli_shutdown(int sig);

#endif

