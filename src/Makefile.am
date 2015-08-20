# Copyright (C) 2006-2013 Free Software Foundation, Inc.
# This Makefile.am is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.

bin_PROGRAMS = udptun

udptun_SOURCES = udptun.c sock.c cli.c serv.c tunalloc.c debug.h udptun.h sock.h cli.h serv.h tunalloc.h
udptun_CFLAGS = ${GLIB_CFLAGS} \
                ${GLIB2_CFLAGS}
udptun_LDFLAGS = ${GLIB_LIBS} \
                ${GLIB2_LIBS}
#`pkg-config --cflags glib-2.0` && `pkg-config --libs glib-2.0`
