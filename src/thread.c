/**
 * \file thread.c
 * \brief The pthread wrappers
 * \author k.edeline
 * \version 0.1
 */

#include "thread.h"
#include "destruct.h"
#include "sock.h"

/**
 * \var pthread_barrier_t barr
 * \brief The synchronization barrier.
 */
pthread_barrier_t barr;


void init_barrier(int nthreads) {
   pthread_barrier_init(&barr, NULL, nthreads);
   debug_print("barrier initialized with %d threads\n", nthreads);
}

void destroy_barrier() {
   pthread_barrier_destroy(&barr);
}

void synchronize() {
   int ret = pthread_barrier_wait(&barr);
   if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) 
      die("pthread_barrier_wait");
}

pthread_t xthread_create(void *(*start_routine) (void *), void *args) {
   pthread_t thread_id;
   if (pthread_create(&thread_id, NULL, start_routine, args) < 0) 
      die("pthread_create");
   set_pthread(thread_id);
   return thread_id;
}


