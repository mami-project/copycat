/**
 * \file thread.h
 * \brief The pthread wrappers prototypes.
 * \author k.edeline
 * \version 0.1
 */
#ifndef _UDPTUN_THREAD_H
#define _UDPTUN_THREAD_H

#include <pthread.h>

/**
 * \fn void xthread_create(void *(*start_routine) (void *), void *args)
 * \brief run a thread (pthread.h)
 *
 * \param start_routine A pointer to the thread function
 * \param args Arguments to be passed to the thread function
 * \return pthread_t
 */ 
pthread_t xthread_create(void *(*start_routine) (void *), void *args);

#endif
