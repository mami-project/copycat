/*
 * cli.h: client
 * 
 *
 * @author k.edeline
 */
#ifndef _UDPTUN_CLI_H
#define _UDPTUN_CLI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "debug.h"
#include "udptun.h"
#include "sock.h"

void tun_cli(struct arguments *);

#endif
