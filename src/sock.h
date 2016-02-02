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

#ifndef UDPTUN_SOCK_H
#define UDPTUN_SOCK_H

#include "sysconfig.h"
#if defined(BSD_OS)
//#include <net/bpf.h>
#elif defined(LINUX_OS)
#  include <linux/filter.h>
#endif

#include <netinet/in.h>
#include <sys/time.h>

#include "udptun.h"
#include "state.h"
char *addr_to_itf(char *addr);
/**
 * \fn int udp_sock(int port)
 * \brief Create and bind a UDP DGRAM socket.
 *
 * \param port The port for the bind call.
 * \param register_gc Register fd to garbage collector.
 * \return The socket fd.
 */ 
int udp_sock(int port, uint8_t register_gc);

#if defined(LINUX_OS)
/**
 * \fn int raw_tcp_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev)
 * \brief Create and bind a TCP RAW socket.
 *    Equivalent to raw_sock(addr, port, bpf, dev, IPPROTO_TCP).
 *    This function is planetlab-specific.
 *
 * \param port The port for the bind call.
 * \param bpf A pointer to a BPF to be attached or NULL.
 * \param dev A pointer to the name of the device to bind. 
 * \return The socket fd.
 */ 
int raw_tcp_sock(int port, const struct sock_fprog * bpf, const char *dev);

/**
 * \fn int raw_sock(const char *addr, int port, const struct sock_fprog * bpf, const char *dev, int proto)
 * \brief Create and bind a RAW socket.
 *    This function is planetlab-specific.
 *
 * \param port The port for the bind call.
 * \param bpf A pointer to a BPF to be attached or NULL.
 * \param dev A pointer to the name of the device to bind. 
 * \param proto The protocol of the raw socket (planetlab-specific).
 * \return The socket fd.
 */ 
int raw_sock(int port, const struct sock_fprog * bpf, const char *dev, int proto);
#endif

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
 * \brief recv syscall wrapper that does not dies with failure.
 *
 * \param fd The file descriptor of the receiving socket. 
 * \param buf A pointer to the buffer.
 * \param buflen The size of the buffer.
 * \return The amount of bytes received.
 */ 
int xrecv(int fd, void *buf, size_t buflen);

/**
 * \fn int xselect(fd_set *input_set, int fd_max, struct timeval *tv, int timeout)
 * \brief select wrapper
 *
 * \param input_set fd set
 * \param fd_max max fd value
 * \param tv a pointer to a struct timeval
 * \param timeout The timeout value, -1 for infinite
 * \return The amount of bytes received.
 */ 
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
 * \param fd_out The fd to forward icmp to, ignore if state is NULL
 * \param state udptun state to forward or NULL
 * 
 * \return 0 if an error msg was received, 
 *         a negative value if an error happened
 */ 
int xrecverr(int fd, void *buf, size_t buflen, int fd_out, struct tun_state *state);

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

/**
 * \fn int xfwrite(FILE *fp, char *buf, int size, int nmemb)
 * \brief fwrite syscall wrapper that dies with failure.
 *
 * \param fp The file pointer
 * \param buf A pointer to the buffer.
 * \param size The size of data elements to write
 * \param nmemb The number of data elements to write
 * \return The amount of bytes written.
 */ 
int xfwrite(FILE *fp, char *buf, int size, int nmemb);

/**
 * \fn void die(char *s)
 * \brief Exit with an error message.
 *
 * \param s The error message.
 */ 
void die(char *s);

#endif

