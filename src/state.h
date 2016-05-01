/**
 * \file state.h
 * \brief This contains state-related functions & structs.
 * \author k.edeline
 * \version 0.1
 */

#ifndef UDPTUN_STATE_H
#define UDPTUN_STATE_H

#include <glib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

/** 
 * \struct tun_rec
 *	\brief Represents a peer of the node.
 */
struct tun_rec {
   struct sockaddr *sa4;        /*!<  The v4 address of the client. */
   unsigned int     slen4;      /*!<  The size of the v4 sockaddr. */
   in_addr_t        priv_addr4; /*!<  The private v4 address in network byte order to be used as a key */

   struct sockaddr *sa6;        /*!<  The v6 address of the client. */
   unsigned int     slen6;      /*!<  The size of the v6 sockaddr. */
   unsigned char   priv_addr6[16];
   //struct in6_addr  priv_addr6;  /*!<  The private v6 address in network byte order to be used as a key */

   int              sport;     /*!<  The udp source port. */
};

/** 
 * \struct tun_state 
 *	\brief The state of the node.
 */
struct tun_state {
   /* From command-line arguments  */
   struct arguments *args;       /*!< The arguments */

   /* Modes */
   uint8_t planetlab;          /*!<  PlanetLab mode */
   uint8_t freebsd;            /*!<  FREEBSD mode */
   uint8_t ipv6;               /*!< IPv6 mode */
   uint8_t dual_stack;         /*!< Dual stack mode */

   /* From destination file */
   GHashTable      *serv;        /*!<  Source port to public address lookup table. */
   GHashTable      *cli4;        /*!<  Private IPv4 address to public address lookup table. */
   GHashTable      *cli6;        /*!<  Private IPv6 address to public address lookup table. */
   struct tun_rec **cli_private; /*!<  Destination list. (private sockaddr's) */
   struct tun_rec **cli_public;  /*!<  Destination list. (public sockaddr's) */ 
   uint8_t sa_len;               /*!<  Number of destinations. */

   /* From cfg file */
   char    *tun_if;            /*!< The tun interface name. */
   char    *default_if;         /*!< The default interface name. */
   char    *private_addr4;       /*!< The private ip address */
   char    *private_mask4;       /*!< The private ip mask */
   char    *private_addr6;      /*!< The private ipv6 address */
   char    *private_mask6;      /*!< The private ipv6 mask */
   char    *public_addr4;        /*!< The public ip address */
   char    *public_addr6;       /*!< The public ipv6 address */

   uint16_t port;               /*!< The UNIQUE per-peer port number */
   uint16_t public_port;        /*!< The udp listen port */
   uint16_t private_port;       /*!< The tcp listen port */

   uint16_t tcp_snd_timeout;    /*!< TCP client send timeout */
   uint16_t tcp_rcv_timeout;    /*!< TCP client receive timeout */
   int16_t  inactivity_timeout; /*!< Inactivity timeout */
   uint16_t initial_sleep;      /*!< Initial sleep time (client & peer) */

   char    *serv_file;          /*!< The server file location */
   char    *cli_dir;            /*!< The data directory (for client) */
   char    *out_dir;            /*!< The output directory */
   /* cli_dir+macro from udptun.h */
   char    *cli_file_tun4;       /*!< The client file location */
   char    *cli_file_notun4;     /*!< The client file location */
   char    *cli_file_tun6;       /*!< The client file location */
   char    *cli_file_notun6;     /*!< The client file location */

   uint32_t buf_length;         /*!< buffer length */
   uint32_t backlog_size;       /*!< backlog size  */
   uint32_t fd_lim;             /*!< max simultaneously open fd */
   
   uint32_t max_segment_size;   /*!< The value passed as TCP_MAXSEG 
                                     optval (max mss) for tun flow */
};

/**
 * \fn struct tun_state *init_tun_state(struct arguments *args)
 * \brief Initialize the server state.
 *
 * \param args The server arguments.
 * \return The server state.
 */ 
struct tun_state *init_tun_state(struct arguments *args);

/**
 * \fn void free_tun_state(struct tun_state *state)
 * \brief Free the server state.
 *
 * \param state The server state.
 */ 
void free_tun_state(struct tun_state *state);

/**
 * \fn struct tun_rec *init_tun_rec()
 * \brief Allocate a tun_rec structure.
 *
 * \return The allocated structure. 
 */
struct tun_rec *init_tun_rec(struct tun_state *state);

/**
 * \fn void free_tun_rec(struct tun_rec *rec)
 * \brief Free a tun_rec structure.
 *
 * \param rec The tun_rec structure. 
 */
void free_tun_rec(struct tun_rec *rec);

#endif

