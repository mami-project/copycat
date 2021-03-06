/**
 * \file thread.h
 * \brief The pthread wrappers prototypes.
 * \author k.edeline
 * \version 0.1
 */
#ifndef UDPTUN_THREAD_H
#define UDPTUN_THREAD_H

#include <pthread.h>

/**
 * \fn void xthread_create(void *(*start_routine) (void *), void *args)
 * \brief run a thread (pthread.h)
 *
 * \param start_routine A pointer to the thread function
 * \param args Arguments to be passed to the thread function
 * \param garbage 1 to add to garbage collector, 0 not to
 * \return pthread_t
 */ 
pthread_t xthread_create(void *(*start_routine) (void *), void *args, int garbage);

/**
 * \fn void init_barrier(int nthreads)
 * \brief Initialize synchronization barriers
 *
 * \param nthreads The number of threads to be sync-ed
 */
void init_barrier(int nthreads);

/**
 * \fn void destroy_barrier()
 * \brief Destroy the sync barriers.
 *
 */
void destroy_barrier();

/**
 * \fn void synchronize()
 * \brief Sync the threads
 *
 */
void synchronize();

#endif

