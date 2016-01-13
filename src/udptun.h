/**
 * \file udptun.h
 * \brief This contains the argument structures and macros.
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_MAIN_H
#define _UDPTUN_MAIN_H

#include <sys/types.h>

/** 
 * \def __BUFFSIZE
 * \brief The size of the client and server buffers.
 */
#define __BUFFSIZE 8192

/**
 * \def __CLOSE_TIMEOUT
 * \brief The time to wait for delayed finack/ack while closing 
 *  a connection (sec).
 */
#define __CLOSE_TIMEOUT 1

/** 
 * \struct arguments
 *	\brief The programs arguments.
 */
struct arguments {
   enum { CLI_MODE, SERV_MODE, FULLMESH_MODE, NONE_MODE } mode; /*!<  The tunnelling mode. */
   uint8_t verbose;            /*!<  verbose mode */
   uint8_t silent;             /*!<  silent mode */
   uint8_t planetlab;          /*!<  PlanetLab mode */
   uint8_t freebsd;            /*!<  FREEBSD mode */

   uint8_t ipv6;               /*!< IPv6 mode */
   uint8_t dual_stack;         /*!< Dual stack mode */

   char *config_file;          /*!< The destination file  */
   char *dest_file;            /*!< The destination file  */
   uint8_t inactivity_timeout; /*!< The inactivity timeout */
};

#include "debug.h"
#include "sock.h"
#include "cli.h"
#include "serv.h"
#include "peer.h"

/**
 * \def max(a,b)
 * \brief max macro with type checking.
 */
#define max(a,b) \
   __extension__({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#endif

