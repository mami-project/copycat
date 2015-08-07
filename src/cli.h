/*
 * cli.h: client
 * 
 *
 * @author k.edeline
 */
#ifndef __UDP_TUN_CLI__
#define __UDP_TUN_CLI__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

//#include "udptun.h"
#include "sock.h"

void tun_cli(struct arguments *);

#endif
