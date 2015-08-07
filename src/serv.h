/*
 * serv.h: server
 * 
 *
 * @author k.edeline
 */
#ifndef __UDP_TUN_SERV__
#define __UDP_TUN_SERV__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

//#include "udptun.h"
#include "sock.h"

void tun_serv(struct arguments *);

#endif
