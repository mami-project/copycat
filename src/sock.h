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

#include <netinet/in.h>
#include <linux/filter.h>
#include <sys/time.h>

#include "udptun.h"
#include "state.h"

/**
 * \fn int udp_sock(int port)
 * \brief Create and bind a UDP DGRAM socket.
 *
 * \param port The port for the bind call.
 * \return The socket fd.
 */ 
int udp_sock(int port);

/**
 * \fn int raw_tcp_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev)
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
 * \fn int raw_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev, int proto)
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
// xrecv and send SIGTERM signal to p if recv raised an error
int xrecvnkill(int fd, void *buf, size_t buflen, pid_t p);

int xselect(fd_set *input_set, int fd_max, struct timeval *tv, int timeout);

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
 * \fn int xrecverr(int fd, void *buf, size_t buflen)
 * \brief Receive an error msg from MSG_ERRQUEUE and print a description 
 *        of it via the debug macro.
 *
 * \param fd The socket fd
 * \param buf The buffer to write err msg to
 * \param buflen The len of buf 
 * 
 * \return 0 if an error msg was received, 
 *         a negative value if an error happened
 */ 
int xrecverr(int fd, void *buf, size_t buflen);
int xfwerr(int fd, void *buf, size_t buflen, int fd_out, struct tun_state *state);
/**
 * \fn int xread(int fd, char *buf, int buflen)
 * \brief read syscall wrapper that dies with failure.
 *
 * \param fd The file descriptor of the receiving socket. 
 * \param buf A pointer to the buffer.
 * \param buflen The size of the buffer.
 * \return The amount of bytes read.
 */ 
int xread(int fd, char *buf, int buflen);

/**
 * \fn int xwrite(int fd, char *buf, int buflen)
 * \brief write syscall wrapper that dies with failure.
 *
 * \param fd The file descriptor of the sending socket.
 * \param buf A pointer to the buffer.
 * \param buflen The size of the buffer.
 * \return The amount of bytes written.
 */ 
int xwrite(int fd, char *buf, int buflen);

int xfwrite(FILE *fp, char *buf, int size, int nmemb);

/**
 * \fn void die(char *s)
 * \brief Exit with an error message.
 *
 * \param s The error message.
 */ 
void die(char *s);

#endif

