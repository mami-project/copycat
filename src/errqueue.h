#ifndef _BITS_ERRQUEUE_H
#define _BITS_ERRQUEUE_H

#include <sys/types.h>
#include <sys/socket.h>

struct sock_extended_err
  {
    u_int32_t ee_errno;
    u_int8_t ee_origin;
    u_int8_t ee_type;
    u_int8_t ee_code;
    u_int8_t ee_pad;
    u_int32_t ee_info;
    u_int32_t ee_data;
  };

#define SO_EE_ORIGIN_NONE  0
#define SO_EE_ORIGIN_LOCAL 1
#define SO_EE_ORIGIN_ICMP  2
#define SO_EE_ORIGIN_ICMP6 3

#define SO_EE_OFFENDER(see)	\
  ((struct sockaddr *)(((struct sock_extended_err)(see))+1))

#endif 
