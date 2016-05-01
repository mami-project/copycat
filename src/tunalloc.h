/*
 * \file tunalloc.h
 * \brief tunnaloc header
 * 
 * \author k.edeline
 * \version 0.1
 */
#ifndef UDPTUN_TUNALLOC_H
#define UDPTUN_TUNALLOC_H
 
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
char *create_tun4(const char *ip, const char *prefix, char *dev, int *tun_fds);
char *create_tun46(const char *ip, const char *prefix, char *dev, int *tun_fds);
char *create_tun6(const char *ip, const char *prefix, char *dev, int *tun_fds);

#  if defined(LINUX_OS)
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

#     ifdef IFF_MULTI_QUEUE

/**
 * \fn int tun_alloc_mq(char *dev, int queues, int *fds)
 * \brief
 *
 * \param dev The desired interface name
 * \param queues The desired amount of queue
 * \param fds A pre-allocated array of size <queue> to be
 *       filled with each queue fds.
 * \return 0 on success, -1 on error
 */
int tun_alloc_mq(char *dev, int queues, int *fds);

/**
 * \fn int tun_set_queue(int fd, int enable)
 * \brief Attach/Detach a queue
 *
 * \param fd The queue fd
 * \param enable 1 To attach the queue, 0 to detach it
 * \return 0 on success, -1 on error
 */
int tun_set_queue(int fd, int enable);

#     endif

#  endif

#endif
