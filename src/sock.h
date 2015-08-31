/**
 * \file sock.h
 * \brief Socket handling.
 *
 *    This contains the prototypes for system calls wrappers, 
 *    socket and BPF creation functions, tun interface creation
 *    functions, network utility functions and die().
 *    Note that raw socket and tun interface related functions are 
 *    Planetlab-specific.
 *
 * \author k.edeline
 * \version 0.1
 */

#ifndef _UDPTUN_SOCK_H
#define _UDPTUN_SOCK_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/filter.h>
#include <netinet/in.h>

#include "debug.h"
#include "tunalloc.h"

/**
 * \def __BUFFSIZE
 * \brief The size of the client and server buffers.
 */
#define __BUFFSIZE 8192

/**
 * \fn int udp_sock(int port)
 * \brief Create and bind a UDP DGRAM socket.
 *
 * \param port The port for the bind call.
 * \return The socket fd.
 */ 
int udp_sock(int port);

/**
 * \fn int udp_sock(int port)
 * \brief Create and bind a TCP RAW socket.
 *    Equivalent to raw_sock(addr, port, bpf, dev, IPPROTO_TCP).
 *    This function is planetlab-specific.
 *
 * \param addr The address for the bind call.
 * \param port The port for the bind call.
 * \param bpf A pointer to a BPF to be attached or NULL.
 * \param dev A pointer to the name of the device to bind. 
 * \return The socket fd.
 */ 
int raw_tcp_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev);

/**
 * \fn int udp_sock(int port)
 * \brief Create and bind a RAW socket.
 *    This function is planetlab-specific.
 *
 * \param addr The address for the bind call.
 * \param port The port for the bind call.
 * \param bpf A pointer to a BPF to be attached or NULL.
 * \param dev A pointer to the name of the device to bind. 
 * \param proto The protocol of the raw socket (planetlab-specific).
 * \return The socket fd.
 */ 
int raw_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev, int proto);

/**
 * \fn struct sock_fprog *gen_bpf(const char *dev, const char *addr, int sport, int dport)
 * \brief Create a Berkeley Packet Filter (BPF). Bind it to a socket.
 * 
 *    The filter is equivalent to $tcpdump -i dev 'src port sport and dst port dport'
 *
 * \param dev The interface of the socket. 
 * \param addr The address of the socket.
 * \param sport The source port to filter or 0 for no filtering.
 * \param dport The destination port to filter or 0 for no filtering.
 * \return 
 */ 
struct sock_fprog *gen_bpf(const char *dev, const char *addr, int sport, int dport);

/**
 * \fn int xsendto(int fd, struct sockaddr *sa, const void *buf, size_t buflen)
 * \brief sendto syscall wrapper that dies with failure.
 *
 * \param fd The file descriptor of the sending socket. 
 * \param sa The address of the target.
 * \param buf A pointer to the buffer.
 * \param buflen The size of the buffer.
 * \return The amount of bytes sent.
 */ 
int xsendto(int fd, struct sockaddr *sa, const void *buf, size_t buflen);

/**
 * \fn int xrecv(int fd, void *buf, size_t buflen)
 * \brief recv syscall wrapper that dies with failure.
 *
 * \param fd The file descriptor of the receiving socket. 
 * \param buf A pointer to the buffer.
 * \param buflen The size of the buffer.
 * \return The amount of bytes received.
 */ 
int xrecv(int fd, void *buf, size_t buflen);

/**
 * \fn int xrecvfrom(int fd, struct sockaddr *sa, unsigned int *salen, void *buf, size_t buflen)
 * \brief recvfrom syscall wrapper that dies with failure.
 *
 * \param fd The file descriptor of the receiving socket. 
 * \param sa modified on return to indicate the source address.
 * \param salen modified on return to indicate the actual size of the source address.
 * \param buf A pointer to the buffer.
 * \param buflen The size of the buffer.
 * \return The amount of bytes received.
 */ 
int xrecvfrom(int fd, struct sockaddr *sa, unsigned int *salen, void *buf, size_t buflen);

/**
 * \fn int xread(int fd, char *buf, int n)
 * \brief read syscall wrapper that dies with failure.
 *
 * \param fd The file descriptor of the receiving socket. 
 * \param buf A pointer to the buffer.
 * \param buflen The size of the buffer.
 * \return The amount of bytes read.
 */ 
int xread(int fd, char *buf, int buflen);

/**
 * \fn int xwrite(int fd, char *buf, int n)
 * \brief write syscall wrapper that dies with failure.
 *
 * \param fd The file descriptor of the sending socket.
 * \param buf A pointer to the buffer.
 * \param buflen The size of the buffer.
 * \return The amount of bytes written.
 */ 
int xwrite(int fd, char *buf, int buflen);

/**
 * \fn char *create_tun(const char *ip, const char *prefix, int nat, int *tun_fds)
 * \brief Allocate and set up a tun interface.
 *
 *    This function is specific to planetlab.
 *
 * \param ip The address of the interface.
 * \param prefix The prefix of the virtual network.
 * \param nat NAT the tun interface or not.
 * \param tun_fds A pointer to an int to be set to the tun interface fd.
 * \return A pointer (malloc) to the interface name.
 */ 
char *create_tun(const char *ip, const char *prefix, int nat, int *tun_fds);

/**
 * \fn struct sockaddr_in *get_addr(const char *addr, int port)
 * \brief Allocate an AF_INET socket address structure.
 *
 * \param addr The sockaddr address.
 * \param port The sockaddr port.
 * \return A pointer (malloc) to the created struct sockaddr_in
 */ 
struct sockaddr_in *get_addr(const char *addr, int port);

/**
 * \fn void die(char *s)
 * \brief Exit with an error message.
 *
 * \param s The error message.
 */ 
void die(char *s);

#endif

