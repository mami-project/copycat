/**
 * \file udptun.c
 * \brief This contains the main() and argument parsing functions, and help messages.
 * \author k.edeline
 * \version 0.1
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include "udptun.h"

/* argp variables and structs */

const char *program_version = "udptun 0.1";
const char*   optstring     = ":abcd:fhi:nNo:pP:qr:sS:tUvV62";
const char* arg_help = "Usage: udptun [OPTION...] -s -o udptun.cfg -d dst.txt\n"
"  or:  udptun [OPTION...] -c -o udptun.cfg -d dst.txt\n"
"  or:  udptun [OPTION...] -f -o udptun.cfg -d dst.txt\n\n"
"forward tcp packets to/from a udp tunnel\n\n"

"  -d, --dest-file FILE         Destination file\n"
"  -o, --config FILE            Configuration file\n"
"\n"
"  -c, --client                 Client mode\n"
"  -s, --server                 Server mode\n"
"  -f, --fullmesh               Fullmesh mode (both client and server)\n"
"\n"
"  -U, --udp                    UDP outer transport\n"
"  -N, --non-udp                non-UDP outer transport\n"
"\n"
"  -r, --raw-header BYTES       Raw header (hex string)\n"
"  -S, --raw-header-size SIZE   Raw header size (number of bytes)\n"
"  -P, --protocol-num NUM       Protocol\n"
"\n"
"  -b, --freebsd                FREEBSD mode\n"
"  -p, --planetlab              PlanetLab mode\n"
"\n"
"  -2, --dual-stack             IPv4-IPv6 mode\n"
"  -6, --ipv6                   IPv6 mode\n"
"\n"
"  -a, --parallel               Client parallel flows scheduling mode (default)\n"
"  -t, --tun-first              Client tunnel first flows scheduling mode\n"
"  -n, --notun-first            Client notunnel first flows scheduling mode\n"
"\n"
"  -q, --quiet                  Don't produce any output\n"
"  -i, --run-id ID              Run ID (in pcap name)\n"
"\n"
"  -v, --verbose                Produce verbose output\n"
"  -h, --help                   Give this help list\n"
"  -V, --version                Print program version\n\n"
"Report bugs to korian.edeline@ulg.ac.be\n";

/**
 * \fn static int parse_args(int key, char *arg, struct arguments *args)
 * \brief Parse one argument.
 */
static int parse_arg(int key, char *optarg, int optopt, struct arguments *args);

/**
 * \fn static void init_args(struct arguments *args)
 * \brief Intialize the arguments to default values.
 */
static void init_args(struct arguments *args);

/**
 * \fn static void print_args(struct arguments *args)
 * \brief Print the arguments.
 */
static void print_args(struct arguments *args);

/**
 * \fn static int validate_args(struct arguments *args)
 * \brief Validate the arguments.
 */
static int validate_args(struct arguments *args);

/**
 * \fn static int parse_args(int argc, char *argv[], struct arguments *args)
 * \brief 
 */
static int parse_args(int argc, char *argv[], struct arguments *args);

int parse_args(int argc, char *argv[], struct arguments *args) {
   int           val = 0;
   extern char*  optarg;
   extern int    optopt;

   while((val = getopt(argc, argv, optstring))!= EOF) {
      if (parse_arg(val, optarg, optopt, args) < 0) {
         printf("%s", arg_help);
         return -1;
      } 
   }
   return 0;
}

int parse_arg(int key, char *optarg, int optopt, struct arguments *args) {
   switch (key) {
      case 'q':
         args->silent = 1; break;
      case 'v':
         args->verbose = 1; break;
      case 'c': 
         args->mode = CLI_MODE; break;
      case 's': 
         args->mode = SERV_MODE; break;
      case 'f':
         args->mode = FULLMESH_MODE; break;
      case 'p':
         args->planetlab = 1; break;
      case 'b':
         args->freebsd = 1; break;
      case '6':
         args->ipv6 = 1; break;
      case 'a':
         args->cli_mode = PARALLEL_MODE; break;
      case 't':
         args->cli_mode = TUN_FIRST_MODE; break;
      case 'n':
         args->cli_mode = NOTUN_FIRST_MODE; break;
      case '2':
         args->dual_stack = 1; break;
      case 'U':
         args->udp = 1;
         break;
      case 'N':
         args->udp = 0;
         break;
      case 'r':
         args->raw_header = optarg;
         break;
      case 'S':
         args->raw_header_size = strtol(optarg, NULL, 10);
         break;
      case 'P':
         args->protocol_num = strtol(optarg, NULL, 10);
         break;
      case 'd':
         args->dest_file = optarg; break;
      case 'o':
         args->config_file = optarg; break;
      case 'i':
         args->run_id = optarg; break;
      case '?':
         printf("Option -%c not supported.\n", optopt);
         return -2;
      case 'V':
         printf("%s\n", program_version);
         return -1;
      case 'h':
         return -1;
      default: 
         return -1;
   }   
   return 0;
}

void init_args(struct arguments *args) {
   args->mode            = NONE_MODE;
   args->cli_mode        = PARALLEL_MODE; 
   args->verbose         = 0;
   args->silent          = 0;
   args->planetlab       = 0;
   args->freebsd         = 0;
   args->ipv6            = 0;
   args->dual_stack      = 0;
   args->udp             = 1;
   args->raw_header_size = 0;    
   args->protocol_num    = 0;    

   args->config_file = NULL;
   args->dest_file   = NULL;
   args->run_id      = NULL;
   args->raw_header  = NULL;

   args->inactivity_timeout = 0;
}

void print_args(struct arguments *args) {
   debug_print("verbose:%d\nsilent:%d\n",args->verbose,args->silent);
   if (args->planetlab) debug_print("PlanetLab mode\n");
   if (args->freebsd) debug_print("FREEBSD mode\n");
   if (args->ipv6) debug_print("IPv6 mode\n");
   if (args->dual_stack) debug_print("Dual Stack mode\n");
   debug_print("cfg file:%s\n", args->config_file);

   switch (args->mode) {
      case CLI_MODE:
         debug_print("client mode\n");
         debug_print("dest file:%s\n", args->dest_file);
         break;
      case SERV_MODE:
         debug_print("server mode\n");
         break;
      case FULLMESH_MODE:
         debug_print("fullmesh mode\n");
         debug_print("dest file:%s\n", args->dest_file);
         break;
      default:
         debug_print("unknown mode\n");
         break;
   }
   if (args->mode == CLI_MODE || args->mode == FULLMESH_MODE) {
      switch (args->cli_mode) {
         case PARALLEL_MODE:
            debug_print("parallel flow scheduling mode\n");
            break;
         case TUN_FIRST_MODE:
            debug_print("tunnel-first flow scheduling mode\n");
            break;
         case NOTUN_FIRST_MODE:
            debug_print("notunnel-first flow scheduling mode\n");
            break;
         default:
            debug_print("unknown scheduling mode\n");
            break;
      }
   }

   if (args->udp) {
      debug_print("UDP mode\n");
      debug_print("extra header size %d\n", args->raw_header_size);
   } else {
      debug_print("non-UDP/RAW mode\n");
      debug_print("protocol number %d\n", args->protocol_num);
      debug_print("extra header size %d\n", args->raw_header_size);
   }  
   debug_print("extra header:%s\n", args->raw_header);
}

int validate_args(struct arguments *args) {
   if (!args->config_file) {
      errno=EINVAL;
      die("set a configuration file (udptun.cfg)");
   } 

   switch (args->mode) {
      case FULLMESH_MODE:
      case CLI_MODE:
         if (!args->dest_file) {
            errno=EINVAL;
            die("set a destination file (dest.txt)");
         } 

         if (args->raw_header && !args->raw_header_size) {
            errno=EINVAL;
            die("specify raw header size");
         } 
         break;
      case SERV_MODE:
         break;
      default:
         errno=EINVAL;
         die("set a mode");
         break;
   }

   if (!args->udp && !args->protocol_num) {
      errno=EINVAL;
      die("specifiy a protocol number in non-UDP mode");
   }

   return 0;
}

int main(int argc, char *argv[]) {
   struct arguments args;

   /* Process arguments */
   init_args(&args);
   if (parse_args(argc, argv, &args) < 0) return -1;
   validate_args(&args);
   if (args.verbose) print_args(&args);

   switch (args.mode) {
      case CLI_MODE:
         tun_cli(&args);
         break;
      case SERV_MODE:
         tun_serv(&args);
         break;
      case FULLMESH_MODE:
         tun_peer(&args);
         break;
      default:
         break;
   }

   return 0;
}

