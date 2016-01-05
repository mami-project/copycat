/**
 * \file udptun.c
 * \brief This contains the main() and argument parsing functions, and help messages.
 * \author k.edeline
 * \version 0.1
 */

#include <pthread.h>
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

  {"planetlab",  'p', 0,        0,  "PlanetLab mode" },
  {"freebsd",    'b', 0,        0,  "FREEBSD mode" },
  {"timeout",    't', "TIME",   0,  "Inactivity timeout" },
  {"dest-file",  'd',  "FILE",   0,  "Destination file"},
  {"config",     'o',  "FILE",   0,  "Configuration file"},

  {"udp-daddr",  '1', "STRING", 0, "udp dst addr"},
  {"tcp-daddr",  '2', "STRING", 0, "tcp dst addr"},
  {"tcp-saddr",  '3', "STRING", 0, "tcp src addr"}, //
  {"udp-dport",  '4', "PORT",   0, "udp dst port"},
  {"udp-sport",  '5', "PORT",   0, "udp src port"},
  {"udp-lport",  '6', "PORT",   0, "udp listen port"},
  {"tcp-dport",  '7', "PORT",   0, "tcp dst port"},
  {"tcp-sport",  '8', "PORT",   0, "tcp src port"}, //
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
      case 't':
         arguments->inactivity_timeout = strtol(arg, NULL, 10);
         break;
      case 'd':
         arguments->dest_file = arg;break;
      case 'o':
         arguments->config_file = arg;break;
      case '1':
         arguments->udp_daddr = arg;break;
      case '2':
         arguments->tcp_daddr = arg;break;
      case '3':
         arguments->tcp_saddr = arg;break;
      case '4':
         arguments->udp_dport = strtol(arg, NULL, 10);
         break;
      case '5':
         arguments->udp_sport = strtol(arg, NULL, 10);
         break;
      case '6':
         arguments->udp_lport = strtol(arg, NULL, 10);
         break;
      case '7':
         arguments->tcp_dport = strtol(arg, NULL, 10);
         break;
      case '8':
         arguments->tcp_sport = strtol(arg, NULL, 10);
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
   args->config_file = NULL;
   args->dest_file   = NULL;
   args->udp_daddr   = NULL;
   args->tcp_daddr   = NULL;
   args->tcp_saddr   = NULL;
   args->udp_dport   = 0;
   args->udp_sport   = 0;
   args->udp_lport   = 0;
   args->tcp_dport   = 0;
   args->tcp_sport   = 0;
   args->inactivity_timeout = 0;
}

void print_args(struct arguments *args) {
   fprintf(stderr,"verbose:%d\nsilent:%d\n",args->verbose,args->silent);
   switch (args->mode) {
      case CLI_MODE:
         fprintf(stderr, "client mode:\n");
         fprintf(stderr,"\tudp dst addr:%s\n",args->udp_daddr);
         fprintf(stderr,"\tudp dst port:%d\n",args->udp_dport);
         fprintf(stderr,"\tudp src port:%d\n",args->udp_sport);
         fprintf(stderr,"\ttcp src addr:%s\n",args->tcp_saddr);
         fprintf(stderr,"\ttcp src port:%d\n",args->tcp_sport);
         fprintf(stderr,"\ttcp dst port:%d\n",args->tcp_dport);
         break;
      case SERV_MODE:
         fprintf(stderr, "server mode:\n");
         fprintf(stderr,"\tudp listen port:%d\n",args->udp_lport);
         fprintf(stderr,"\ttcp dst addr:%s\n",args->tcp_daddr);
         fprintf(stderr,"\ttcp dst port:%d\n",args->tcp_dport);
         break;
      case FULLMESH_MODE:
         fprintf(stderr, "fullmesh mode:\n");
         fprintf(stderr,"\tudp dst addr:%s\n",args->udp_daddr);
         fprintf(stderr,"\tudp dst port:%d\n",args->udp_dport);
         fprintf(stderr,"\tudp src port:%d\n",args->udp_sport);
         fprintf(stderr,"\ttcp src addr:%s\n",args->tcp_saddr);
         fprintf(stderr,"\ttcp src port:%d\n",args->tcp_sport);
         fprintf(stderr,"\ttcp dst port:%d\n",args->tcp_dport);
         fprintf(stderr,"\tudp listen port:%d\n",args->udp_lport);
         fprintf(stderr,"\ttcp dst addr:%s\n",args->tcp_daddr);
         fprintf(stderr,"\ttcp dst port:%d\n",args->tcp_dport);
         break;
      default:
         fprintf(stderr, "unknown mode\n");
         break;
   }
}

int validate_args(struct arguments *args) {
   switch (args->mode) {
      case CLI_MODE://TODO
         break;
         if (!args->udp_daddr || !args->udp_dport || !args->udp_sport ||
             !args->tcp_saddr || !args->tcp_sport || !args->tcp_dport) {
            errno=EINVAL;
            die("client args missing");
         } 
         break;
      case SERV_MODE://TODO
         break;
         if (!args->udp_lport || !args->tcp_daddr || !args->tcp_dport) {
            errno=EINVAL;
            die("server args missing");
         }
         break;
      case FULLMESH_MODE:
         break;
         if (!args->udp_daddr || !args->udp_dport || !args->udp_sport ||
             !args->tcp_saddr || !args->tcp_sport || !args->tcp_dport) {
            errno=EINVAL;
            die("fullmesh args missing");
         } 
         break;
      default:
         errno=EINVAL;
         die("set a mode");
   }

   return 0;
}

int main(int argc, char *argv[]) {
   struct arguments args;
   init_args(&args);
   argp_parse(&argp, argc, argv, 0, 0, &args);
   validate_args(&args);
   if (args.verbose) print_args(&args);

   if (args.mode == CLI_MODE) 
      tun_cli(&args);
   else if (args.mode == SERV_MODE) 
      tun_serv(&args);
   else if (args.mode == FULLMESH_MODE) 
      tun_peer(&args);
 
   return 0;
}

