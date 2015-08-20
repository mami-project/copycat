/*
 * debug.h
 * 
 * 
 * 
 * k.edeline
 */
#ifndef DEBUG_H
#define DEBUG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define DEBUG

/* -- Macro Definitions */
#ifdef DEBUG
#define debug_print(fmt, ...) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, ##__VA_ARGS__)
#define DEBUG_TEST 1
#else
#define debug_print(fmt, ...) 
#define DEBUG_TEST 0
#endif /* DEBUG */

/* -- Declarations */

#ifdef DEBUG
extern  int     debug;
#endif

#endif  /* DEBUG_H */
