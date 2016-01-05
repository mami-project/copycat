/**
 * \file icmp.c
 * \brief ICMP handling implementation.
 * \author k.edeline
 * \version 0.1
 */

#include "icmp.h"

void print_icmp_type(uint8_t type, uint8_t code) {

   // icmp msg types
   switch (type) {
      case ICMP_DEST_UNREACH:
         // icmp type 3 codes
         switch (code) {
            case ICMP_NET_UNREACH:
               debug_print("icmp network unreachable\n");
               break;
            case ICMP_HOST_UNREACH:
               debug_print("icmp host unreachable\n");
               break;
            case ICMP_PROT_UNREACH:
               debug_print("icmp protocol unreachable\n");
               break;
            case ICMP_PORT_UNREACH:
               debug_print("icmp port unreachable\n");
               break;
            default:
               debug_print("icmp unreachable code %d\n", code);
               break;
         }
         break;
      case ICMP_SOURCE_QUENCH:
         debug_print("icmp source quench\n");
         break;
      case ICMP_REDIRECT:
         debug_print("icmp redirect\n");
         break;
      case ICMP_TIME_EXCEEDED:
         debug_print("icmp time exceeded\n");
         break;
      case ICMP_PARAMETERPROB:
         debug_print("icmp parameter problem\n");
         break;
      default:
         debug_print("icmp type %d code %d\n", type, code);
         break;
   }
}

