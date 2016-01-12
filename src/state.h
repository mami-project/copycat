/**
 * \file state.h
 * \brief This contains state-related functions & structs.
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_STATE_H
#define _UDPTUN_STATE_H

#include <glib.h>
#include <stdint.h>
#include <netinet/in.h>

/** 
 * \struct tun_rec
 *	\brief A record represents a client.
 */
struct tun_rec {
   struct sockaddr *sa;        /*!<  The address of the client. */
   unsigned int     slen;      /*!<  The size of the sockaddr. */
   int              sport;     /*!<  The udp source port. */
   in_addr_t        priv_addr; /*!<  The private address in network byte order to be used as a key */
};

/** 
 * \struct tun_state 
 *	\brief The state of the server.
 */
struct tun_state {
   /* From command-line arguments  */
   struct arguments *args;       /*!< The arguments */

   /* From destination file */
   GHashTable      *serv;        /*!<  Source port to public address lookup table. */
   GHashTable      *cli;         /*!<  Private address to public address lookup table. */
   struct tun_rec **cli_private; /*!<  Destination list. */
   uint8_t sa_len;               /*!<  Number of destinations. */

   //char            *if_name;   /*!<  The tun interface name. TODO: wished if in arg and final if in state*/

   /* Fields defined in cfg file */
   char    *private_addr;   /*!< The private ip address */
   char    *private_mask;   /*!< The private ip mask */
   char    *private_addr6;  /*!< The private ipv6 address */
   char    *private_mask6;  /*!< The private ipv6 mask */

   char    *public_addr;    /*!< The public ip address */
   char    *public_addr6;   /*!< The public ipv6 address */
   uint16_t port;           /*!< The UNIQUE per-peer port number */

   uint16_t udp_port;       /*!<  The udp listen port */
   uint16_t tcp_port;       /*!<  The tcp listen port */

   uint16_t tcp_snd_timeout; //TODO as arg too
   uint16_t tcp_rcv_timeout;
   int16_t inactivity_timeout;
   uint16_t initial_sleep;
   
   char *cli_file;
   char *serv_file;

   uint32_t buf_length;
   uint32_t backlog_size;
   uint32_t fd_lim;
   
   uint32_t max_segment_size; /*!< The value passed as TCP_MAXSEG optval (max mss) */
};

/**
 * \fn static struct tun_state *init_tun_state(struct arguments *args)
 * \brief Initialize the server state.
 *
 * \param args The server arguments.
 * \return The server state.
 */ 
struct tun_state *init_tun_state(struct arguments *args);

/**
 * \fn static void free_tun_tate(struct tun_state *state)
 * \brief Free the server state.
 *
 * \param state The server state.
 */ 
void free_tun_state(struct tun_state *state);

/**
 * \fn static struct tun_rec *init_tun_rec()
 * \brief Allocate a tun_rec structure.
 *
 * \return The allocated structure. 
 */
struct tun_rec *init_tun_rec();

/**
 * \fn static void free_tun_rec(struct tun_rec *rec)
 * \brief Free a tun_rec structure.
 *
 * \param rec The tun_rec structure. 
 */
void free_tun_rec(struct tun_rec *rec);

#endif
