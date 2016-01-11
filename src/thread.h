/**
 * \file thread.h
 * \brief The pthread wrappers prototypes.
 * \author k.edeline
 * \version 0.1
 */
#ifndef _UDPTUN_THREAD_H
#define _UDPTUN_THREAD_H

void xthread_create(void *(*start_routine) (void *), void *args);

#endif
