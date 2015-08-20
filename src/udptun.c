/*
 * udptun.c: udp tun header
 * 
 *
 * @author k.edeline
 */

#include "udptun.h"

const char *argp_program_version     = "udptun 0.1";
const char *argp_program_bug_address = "korian.edeline@ulg.ac.be";
static char doc[]      = "forward tcp packets to/from a udp tunnel";
static char args_doc[] = "\nSERVER mode usage: -s --udp-lport PORT --tcp-daddr ADDR -tcp-dport PORT\n"
                         "CLIENT mode usage: -c --udp-daddr ADDR --udp-dport PORT --udp-sport PORT"
                         " --tcp-saddr ADDR --tcp-sport PORT --tcp-dport PORT (--tcp-ndport PORT)";
static struct argp_option options[] = { 
  {"verbose",    'v', 0,        0,  "produce verbose output" },
  {"quiet",      'q', 0,        0,  "don't produce any output" },
  {"client",     'c', 0,        0,  "client mode" },
  {"server",     's', 0,        0,  "server mode" },
  {"udp-daddr",  '1', "STRING", 0, "udp dst addr"},
  {"tcp-daddr",  '2', "STRING", 0, "tcp dst addr"},
  {"tcp-saddr",  '3', "STRING", 0, "tcp src addr"}, //
  {"udp-dport",  '4', "PORT",   0, "udp dst port"},
  {"udp-sport",  '5', "PORT",   0, "udp src port"},
  {"udp-lport",  '6', "PORT",   0, "udp listen port"},
  {"tcp-dport",  '7', "PORT",   0, "tcp dst port"},
  {"tcp-sport",  '8', "PORT",   0, "tcp src port"}, //
  {"tcp-ndport", 'n', "PORT",   0, "tcp new dst port, use this if you are going to run both cli and serv on the same host"},
    { 0 } 
};

static error_t parse_args(int key, char *arg, struct argp_state *state);
static void init_args(struct arguments *args);
static void print_args(struct arguments *args);
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
      case '1':
         arguments->udp_daddr = arg;break;
      case '2':
         arguments->tcp_daddr = arg;break;
      case '3':
         arguments->tcp_saddr = arg;break;
      case '4':
          arguments->udp_dport=strtol(arg, NULL, 10);
          break;
      case '5':
          arguments->udp_sport=strtol(arg, NULL, 10);
          break;
      case '6':
          arguments->udp_lport=strtol(arg, NULL, 10);
          break;
      case '7':
          arguments->tcp_dport=strtol(arg, NULL, 10);
          break;
      case '8':
          arguments->tcp_sport=strtol(arg, NULL, 10);
          break;
      case 'n':
          arguments->tcp_ndport=strtol(arg, NULL, 10);
          break;
      case ARGP_KEY_ARG: 
         return 0;
      default: 
         return ARGP_ERR_UNKNOWN;
   }   
   return 0;
}

void init_args(struct arguments *args) {

   args->mode       = NONE_MODE;
   args->verbose    = 0;
   args->silent     = 0;
   args->udp_daddr  = NULL;
   args->tcp_daddr  = NULL;
   args->tcp_saddr  = NULL;
   args->udp_dport  = 0;
   args->udp_sport  = 0;
   args->udp_lport  = 0;
   args->tcp_dport  = 0;
   args->tcp_sport  = 0;
   args->tcp_ndport = 0;
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
         fprintf(stderr,"\ttcp new dst port:%d\n",args->tcp_ndport);
         break;
      case SERV_MODE:
         fprintf(stderr, "server mode:\n");
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
      case CLI_MODE:
         if (!args->udp_daddr || !args->udp_dport || !args->udp_sport ||
             !args->tcp_saddr || !args->tcp_sport || !args->tcp_dport ||
             !args->tcp_ndport) {
            errno=EINVAL;
            die("client args missing");
         } 
         break;
      case SERV_MODE:
         if (!args->udp_lport || !args->tcp_daddr || !args->tcp_dport) {
            errno=EINVAL;
            die("server args missing");
         }
         break;
      default:
         errno=EINVAL;
         die("set a mode");
   }

   return 0;
}


int main(int argc, char *argv[]) {
   /*
    * cli mode: udp daddr, udp dport, udp sport, tcp lport, tcp laddr (*.1), (tcp new_port)
    *
    * serv mode: udp lport, tcp daddr(*.1), tcp dport (+ connection pool based on udp/tcp port)
    *
    * e.g.:
    * 
    */
   debug_print("test\n");
   int z=5;
   debug_print("%d\n",z);
   debug_print("t %s\n","zezer");
   debug_print("\n");

   struct arguments args;
   init_args(&args);
   argp_parse(&argp, argc, argv, 0, 0, &args);
   validate_args(&args);
   if (args.verbose) print_args(&args);

   if (args.mode == CLI_MODE) {
      tun_cli(&args);
   } else if (args.mode == SERV_MODE) {
      tun_serv(&args);
   }
 
   return 0;
}
