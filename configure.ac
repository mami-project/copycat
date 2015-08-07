# Copyright (C) 2006-2013 Free Software Foundation, Inc.
# This configure.ac script is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.

AC_INIT([udptun], [0.1], [korian.edeline@ulg.ac.be])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_PROG_CC_STDC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_CHECK_LIB([pcap], [pcap_compile])
AC_CHECK_FUNCS([inet_ntoa memset socket strerror strtol])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h pcap.h])
AC_FUNC_MALLOC
AC_TYPE_SIZE_T
AC_OUTPUT
