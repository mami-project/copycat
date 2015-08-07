# Copyright (C) 2006-2013 Free Software Foundation, Inc.
# This configure.ac script is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.

AC_INIT([udptun], [0.1], [korian.edeline@ulg.ac.be])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_compile])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h pcap.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa memset select socket strerror strtol])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
