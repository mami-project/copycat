/*
 * udptun.h: udp tun header
 * 
 *
 * @author: k.edeline
 */
#ifndef _UDPTUN_MAIN_H
#define _UDPTUN_MAIN_H

//#define __DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>
#include <errno.h>

#include <sys/types.h>

struct arguments {
    enum { CLI_MODE, SERV_MODE, NONE_MODE } mode;
    int verbose, silent;
    char *udp_daddr, *tcp_daddr, *tcp_saddr;
    int   udp_dport,  udp_sport,  udp_lport;
    int   tcp_dport,  tcp_sport,  tcp_ndport;
};

#include "debug.h"
#include "cli.h"
#include "serv.h"



#define max(a,b) \
   __extension__({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#endif
