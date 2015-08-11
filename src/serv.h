/*
 * serv.h: server
 * 
 *
 * @author k.edeline
 */
#ifndef _UDPTUN_SERV_H
#define _UDPTUN_SERV_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "udptun.h"
#include "sock.h"

#define UDP_TUN_FDLIM 512

void tun_serv(struct arguments *);

#endif
