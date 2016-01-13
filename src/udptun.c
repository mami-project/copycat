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
#include <argp.h>
#include <errno.h>
#include <signal.h>

#include "udptun.h"

/* argp variables and structs */

const char *argp_program_version     = "udptun 0.1";
const char *argp_program_bug_address = "korian.edeline@ulg.ac.be";
static char doc[]      = "forward tcp packets to/from a udp tunnel";
static char args_doc[] = "\nSERVER mode usage: -s (-p) (-f) --udp-lport PORT --tcp-daddr ADDR -tcp-dport PORT\n"
                         "CLIENT mode usage: -c (-p) (-f) --udp-daddr ADDR --udp-dport PORT --udp-sport PORT"
                         " --tcp-saddr ADDR --tcp-sport PORT --tcp-dport PORT";

static struct argp_option options[] = { 
  {"verbose",    'v', 0,        0,  "Produce verbose output" },
  {"quiet",      'q', 0,        0,  "Don't produce any output" },

  {"client",     'c', 0,        0,  "Client mode" },
  {"server",     's', 0,        0,  "Server mode" },
  {"fullmesh",   'f', 0,        0,  "Fullmesh mode (both client and server)" },

  {"ipv6",     '6', 0,        0,  "IPv6 mode" },
  {"ipv4-ipv6",'2', 0,        0,  "IPv4-IPv6 mode" },

  {"planetlab",  'p', 0,        0,  "PlanetLab mode" },
  {"freebsd",    'b', 0,        0,  "FREEBSD mode" },
  {"timeout",    't', "TIME",   0,  "Inactivity timeout" },
  {"dest-file",  'd',  "FILE",   0,  "Destination file"},
  {"config",     'o',  "FILE",   0,  "Configuration file"},
    { 0, 0, 0, 0, 0 } 
};

/**
 * \fn static error_t parse_args(int key, char *arg, struct argp_state *state)
 * \brief Parse one argument.
 */
static error_t parse_args(int key, char *arg, struct argp_state *state);

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

struct argp argp = { options, parse_args, args_doc, doc, 0, 0, 0 };

error_t parse_args(int key, char *arg, struct argp_state *state) {
   struct arguments *arguments = state->input;
   switch (key) {
      case 'q':
         arguments->silent = 1;break;
      case 'v':
         arguments->verbose = 1;break;
      case 'c': 
         arguments->mode = CLI_MODE;break;
      case 's': 
         arguments->mode = SERV_MODE;break;
      case 'f':
         arguments->mode = FULLMESH_MODE; break;
      case 'p':
         arguments->planetlab = 1; break;
      case 'b':
         arguments->freebsd = 1; break;
      case '6':
         arguments->ipv6 = 1; break;
      case '2':
         arguments->dual_stack = 1; break;
      case 't':
         arguments->inactivity_timeout = strtol(arg, NULL, 10);
         break;
      case 'd':
         arguments->dest_file = arg;break;
      case 'o':
         arguments->config_file = arg;break;
         break;
      case ARGP_KEY_ARG: 
         return 0;
      default: 
         return ARGP_ERR_UNKNOWN;
   }   
   return 0;
}

void init_args(struct arguments *args) {
   args->mode        = NONE_MODE;
   args->verbose     = 0;
   args->silent      = 0;
   args->planetlab   = 0;
   args->freebsd     = 0;
   args->ipv6        = 0;
   args->dual_stack  = 0;
   args->config_file = NULL;
   args->dest_file   = NULL;
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
         break;
      case SERV_MODE:
         break;
      default:
         errno=EINVAL;
         die("set a mode");
         break;
   }

   return 0;
}

int main(int argc, char *argv[]) {
   struct arguments args;
   init_args(&args);
   argp_parse(&argp, argc, argv, 0, 0, &args);
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

