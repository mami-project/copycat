/**
 * \file udptun.h
 * \brief This contains the argument structures and macros.
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_MAIN_H
#define _UDPTUN_MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>
#include <errno.h>
#include <sys/types.h>

/** 
 * \struct arguments
 *	\brief The programs arguments.
 */
struct arguments {
   enum { CLI_MODE, SERV_MODE, NONE_MODE } mode; /*!<  The tunnelling mode. */
   int verbose;      /*!<  verbose mode */
   int silent;       /*!<  silent mode */
   char *udp_daddr;  /*!<  The UDP destination address. */
   char *tcp_daddr;  /*!< The TCP destination address. */
   char *tcp_saddr;  /*!<  The TCP source address. */
   int   udp_dport;  /*!<  The UDP destination port. */
   int   udp_sport;  /*!<   The UDP source port. */
   int   udp_lport;  /*!<  The UDP listen port. */
   int   tcp_dport;  /*!<  The TCP destination port. */
   int   tcp_sport;  /*!<  The TCP source port. */
   int   tcp_ndport; /*!<  The TCP destination port to set (Optional). */
};

#include "debug.h"
#include "cli.h"
#include "serv.h"

/**
 * \def max(a,b)
 * \brief max macro with type checking.
 */
#define max(a,b) \
   __extension__({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#endif

