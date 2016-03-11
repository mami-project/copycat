/**
 * \file sysconfig.h
 * \brief OS & libs detection macros
 *
 * \author k.edeline
 * \version 0.1
 */

#ifndef UDPTUN_SYSCONF_H
#define UDPTUN_SYSCONF_H

/* OS */

#if defined(__DragonFly__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
/**
 * BSD OS
 */
#  define BSD_OS

#elif defined(__linux__)
/**
 * Linux OS
 */
#  define LINUX_OS

#elif defined(__APPLE__) && defined(__MACH__)
/**
 * Apple OSX and iOS (Darwin)
 */
#  define MAC_OS

#elif defined(__CYGWIN__) && !defined(_WIN32)
/**
 * POSIX Windows
 */
#  define CYGWIN_OS

#elif defined(_WIN32) || defined(_WIN64)

/**
 * Non-POSIX Windows
 */
#  define WIN_OS
#endif

/* Libs */

/* GLIB versions */
#if defined(HAVE_LIBGLIB_2_0)
#  define GLIB2
#elif defined(HAVE_LIBGLIB)
#  define GLIB1
#endif

#endif 
