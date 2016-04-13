/**
 * \file debug.h
 * \brief Debugging macros.
 * \author k.edeline
 * \version 0.1
 */

#ifndef DEBUG_H
#define DEBUG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/**
 * \def UNUSED
 * \brief Unused var macro.
 */
#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

//#define DEBUG

#ifdef DEBUG

#include <stdio.h>

/**
 * \def debug_print(fmt, ...)
 * \brief Debugging stderr printing macro
 *    Will only print if DEBUG is defined. Otherwise, will be removed.
 */
#define debug_print(fmt, ...) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, ##__VA_ARGS__)

/**
 * \def debug_perror()
 * \brief Debugging stderr errno printing macro
 *    Will only print if DEBUG is defined. Otherwise, will be removed.
 */
#define debug_perror() perror(NULL)

#else

#define debug_print(fmt, ...) 
#define debug_perror()

#endif /* DEBUG */

#endif  /* DEBUG_H */

