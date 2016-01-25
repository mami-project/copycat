/**
 * \file destruct.h
 *    \brief Functions prototypes for destructors.
 * \author k.edeline
 * \version 0.1
 */

#ifndef UDPTUN_DESTRUCT_H
#define UDPTUN_DESTRUCT_H

#include <pthread.h>
#include <sys/types.h>
#include "state.h"

/**
 * \fn void init_destructors()
 * \brief Initialize destructors, call before any other functions
 *        of this module.
 *
 */ 
void init_destructors(struct tun_state *state);

/**
 * \fn void set_pthread(pthread_t t)
 * \brief Register a thread to be killed at destruction time.
 *
 * \param t The thread id
 */ 
void set_pthread(pthread_t t);

/**
 * \fn void set_cpid(pid_t p)
 * \brief Register a process to be killed at destruction time.
 *
 * \param p The process id
 */ 
void set_cpid(pid_t p);

/**
 * \fn void set_fd(int fds)
 * \brief Register a fd to be closed at destruction time.
 *
 * \param fds The fd
 */ 
void set_fd(int fds);


#endif 

