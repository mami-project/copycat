/**
 * \file thread.c
 * \brief The pthread wrappers
 * \author k.edeline
 * \version 0.1
 */

#include "thread.h"
#include "destruct.h"
#include "sock.h"

pthread_t xthread_create(void *(*start_routine) (void *), void *args) {
   pthread_t thread_id;
   if (pthread_create(&thread_id, NULL, start_routine, args) < 0) 
      die("pthread_create");
   set_pthread(thread_id);
   return thread_id;
}

