# Copyright (C) 2006-2013 Free Software Foundation, Inc.
# This configure.ac script is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.

AC_INIT([udptun], [0.1], [korian.edeline@ulg.ac.be])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
PKG_PROG_PKG_CONFIG

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_compile])
AC_CHECK_LIB([glib-2.0], [g_hash_table_lookup], [],
   [AC_CHECK_LIB([glib], [g_hash_table_lookup])]
)

# Checks for modules.
GLIB2=[glib-2.0]
GLIB=[glib]
PKG_CHECK_MODULES(GLIB2, [glib-2.0 >= 2.0], [],
   [PKG_CHECK_MODULES(GLIB, [glib >= 1.2.10])]
)

# Checks for header files.
AC_HEADER_STDC
#AC_CHECK_HEADER(glib.h)
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h pcap.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa memset select socket strdup strtol])

#PKG_CHECK_MODULES(GLIB, [glib-2.0])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
