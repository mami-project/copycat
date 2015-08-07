/*
 * udptun.h: udp tun header
 * 
 * VN: 192.168.2.0/24
 * VNI: tun639-0
 * k.edeline
 */
#ifndef __UDP_TUN_MAIN__
#define __UDP_TUN_MAIN__

#define __DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>
#include <errno.h>

#include <sys/types.h>

#include "config.h"

struct arguments;

#include "cli.h"
#include "serv.h"

struct arguments {
    enum { CLI_MODE, SERV_MODE, NONE_MODE } mode;
    int verbose, silent;
    char *udp_daddr, *tcp_daddr, *tcp_laddr;
    int   udp_dport,  udp_sport,  udp_lport;
    int   tcp_dport,  tcp_lport,  tcp_ndport;
};

void die(char *s);

#endif
