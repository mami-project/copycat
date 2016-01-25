/**
 * \file udptun.h
 * \brief This contains the argument structures and macros.
 * \author k.edeline
 * \version 0.1
 */

#ifndef UDPTUN_MAIN_H
#define UDPTUN_MAIN_H

#include <sys/types.h>

/** 
 * \def BUFF_SIZE
 * \brief The size of the client and server buffers.
 */
#define BUFF_SIZE 8192

/** 
 * \def STR_SIZE
 * \brief The maximal size of a location string.
 */
#define STR_SIZE 512

/**
 * \def CLOSE_TIMEOUT
 * \brief The time to wait for delayed finack/ack while closing 
 *  a connection (sec).
 */
#define CLOSE_TIMEOUT 1

/**
 * \def CLI_TUN_FILE
 * \brief 
 */
#define CLI_TUN_FILE "cli_tun.dat"

/**
 * \def CLI_NOTUN_FILE
 */
#define CLI_NOTUN_FILE "cli_notun.dat"

/** 
 * \struct arguments
 *	\brief The programs arguments.
 */
struct arguments {
   enum { CLI_MODE, SERV_MODE, FULLMESH_MODE, NONE_MODE } mode; /*!<  The tunnelling mode. */
   enum { PARALLEL_MODE, TUN_FIRST_MODE, NOTUN_FIRST_MODE } cli_mode; /*!<  The client scheduling mode. */
   uint8_t verbose;            /*!<  verbose mode */
   uint8_t silent;             /*!<  silent mode */
   uint8_t planetlab;          /*!<  PlanetLab mode */
   uint8_t freebsd;            /*!<  FREEBSD mode */

   uint8_t ipv6;               /*!< IPv6 mode */
   uint8_t dual_stack;         /*!< Dual stack mode */

   char *config_file;          /*!< The configuration file  */
   char *dest_file;            /*!< The destination file  */
   uint8_t inactivity_timeout; /*!< The inactivity timeout */

   char *run_id;               /*!< The run ID */
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

