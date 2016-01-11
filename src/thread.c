/**
 * \file thread.c
 * \brief The pthread wrappers
 * \author k.edeline
 * \version 0.1
 */
#include <pthread.h>

#include "thread.h"
#include "destruct.h"
#include "sock.h"

void xthread_create(void *(*start_routine) (void *), void *args) {
   pthread_t thread_id;
   if (pthread_create(&thread_id, NULL, start_routine, args) < 0) 
      die("pthread_create");
   set_pthread(thread_id);
}

