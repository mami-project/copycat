dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([udptun], [0.1], [korian.edeline@ulg.ac.be])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
PKG_PROG_PKG_CONFIG

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_MAKE_SET
AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
   then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
fi

# Checks for libraries.
#AC_CHECK_LIB(argp, argp_parse)
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB([pcap], [pcap_compile])
AC_CHECK_LIB([glib-2.0], [g_hash_table_lookup], [],
   [AC_CHECK_LIB([glib], [g_hash_table_lookup])]
)

# These libraries have to be explicitly linked in OpenSolaris (from libtrace)
AC_SEARCH_LIBS(getaddrinfo, socket, [], [], -lnsl)
AC_SEARCH_LIBS(inet_ntop, nsl, [], [], -lsocket)

# Checks for modules.
GLIB2=[glib-2.0]
GLIB=[glib]
PKG_CHECK_MODULES(GLIB2, [glib-2.0 >= 2.12], [],
   [PKG_CHECK_MODULES(GLIB, [glib >= 1.2.10])]
)
#AX_PTHREAD()

# Checks for header files.
AC_HEADER_STDC
#AC_CHECK_HEADER(glib.h)
AC_CHECK_HEADERS([pthread.h arpa/inet.h netinet/in.h pcap.h stdlib.h string.h sys/socket.h unistd.h fcntl.h sys/ioctl.h sys/time.h sys/param.h argp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_FORK
AC_CHECK_FUNCS([inet_ntoa memset select socket strdup strtol atexit strerror])

#PKG_CHECK_MODULES(GLIB, [glib-2.0])
AM_CONDITIONAL([HAVE_DOXYGEN],
[test -n "$DOXYGEN"])AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([doc/Doxyfile])])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
