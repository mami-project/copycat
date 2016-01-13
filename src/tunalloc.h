/*
 * \file tunalloc.h
 * \brief tunnaloc header
 * 
 * \author k.edeline
 * \version 0.1
 */
#ifndef _TUNALLOC_H
#define _TUNALLOC_H

//TODO macro for OS identification
//#define _PL_NODE_
 
/**
 * \fn char *create_tun_pl(const char *ip, const char *prefix, int nat, int *tun_fds)
 * \brief Allocate and set up a tun interface.
 *
 *    This function is specific to planetlab.
 *
 * \param ip The address of the interface.
 * \param prefix The prefix of the virtual network.
 * \param nat NAT the tun interface or not.
 * \param tun_fds A pointer to an int to be set to the tun interface fd.
 * \return A pointer (malloc) to the interface name.
 */ 
char *create_tun_pl(const char *ip, const char *prefix, int *tun_fds);

/**
 * \fn char *create_tun(const char *ip, const char *prefix, int nat, int *tun_fds)
 * \brief Allocate and set up a tun interface.
 *
 *    This function is specific to planetlab.
 *
 * \param ip The address of the interface.
 * \param prefix The prefix of the virtual network.
 * \param dev The wished device name, or NULL
 * \deprecated nat NAT the tun interface or not.
 * \param tun_fds A pointer to an int to be set to the tun interface fd.
 * \return A pointer (malloc) to the interface name.
 */ 
char *create_tun(const char *ip, const char *prefix, char *dev, int *tun_fds);

int tun_alloc_mq(char *dev, int queues, int *fds);
int tun_set_queue(int fd, int enable);

#endif
