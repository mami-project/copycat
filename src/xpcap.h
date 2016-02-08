/**
 * \file xpcap.h
 * \brief libpcap wrapper headers
 * \author k.edeline
 * \version 0.1
 */

#ifndef UDPTUN_XPCAP_H
#define UDPTUN_XPCAP_H

#include "sysconfig.h"
#if defined(BSD_OS)
//#   include <net/bpf.h>
#  include <pcap.h>
#elif defined(LINUX_OS)
#  include <linux/filter.h>
#endif

/**
 * \fn void *capture_tun(void *arg)
 * \brief Capture the tunneled flows in a separate thread
 *          and write it to the output directory.
 *   Warning: 
 *          May fails to bind to right interface on certain OSs 
 *          (Fedoras with 3.x kernels)
 *  \param arg The program state (struct tun_state *)
 *
 */
void *capture_tun(void *arg);

/**
 * \fn void *capture_notun(void *arg)
 * \brief Capture the not-tunneled flows in a separate thread
 *          and write it to the output directory.
 * 
 *  \param arg The program state (struct tun_state *)
 *
 */
void *capture_notun(void *arg);

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

#endif

