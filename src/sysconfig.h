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
#define BSD_OS
#endif

/* Libs */

#if defined(HAVE_LIBGLIB_2_0)
#define GLIB2
#elif defined(HAVE_LIBGLIB)
#define GLIB1
#endif

#endif 
