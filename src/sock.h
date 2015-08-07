/*
 * sock.h: socket handling
 *         raw socket/tun itf related functions are PL-specific
 * VN: 192.168.2.0/24
 * VNI: tun*-0
 * @author k.edeline
 */
#ifndef __UDP_TUN_SOCK__
#define __UDP_TUN_SOCK__

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

#include "tunalloc.h"
#include "udptun.h"

#define VSYS_VIFUP_IN "/vsys/vif_up.in"
#define VSYS_VIFUP_OUT "/vsys/vif_up.out"

#define __BUFFSIZE 1440

int udp_sock(int port);
int raw_tcp_sock(const char *addr, int port, const char* dev);
int raw_sock(const char *addr, int port, const char *dev, int proto);

struct sock_fprog *gen_bpf(const char *dev, const char *addr, int sport, int dport);
void xsendto(int fd, struct sockaddr_in * addr, const void *buf, size_t buflen);
int xrecv(int fd, void *buf, size_t buflen);


/**
 * allocate & set up a tun interface 
 * @returns interface name
 *
 **/
char *create_tun(const char *ip, const char *prefix, int nat);

/**
 * @returns sockaddr_in struct with addr&port fields set
 **/
struct sockaddr_in *get_addr(const char *addr, int port);

#endif
