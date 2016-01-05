/**
 * \file state.c
 * \brief State-related features.
 *
 * \author k.edeline
 * \version 0.1
 */

#include "state.h"
#include "udptun.h"
#include "destruct.h"
#include "debug.h"

/**
 * \fn static int parse_dest_file(struct arguments *args, struct tun_state *state)
 * \brief Parse destination file and file hash table with sockaddr's.
 *
 * \param args
 * \param state
 * \return 0 for success, -1 on error (errno is filled)
 */
static int parse_dest_file(struct arguments *args, struct tun_state *state);

static int parse_cfg_file(struct tun_state *state);

int parse_cfg_file(struct tun_state *state) {
   FILE *fp = fopen(state->args->config_file, "r");
   if(!fp) {
      errno=ENOENT;
      return -1;
   }
   //TODO: fixed cfg location
   int sport, count=0;
   char key[256], val[256], c;
   /* build port to public addr lookup table */
   while ((c =fgetc(fp)) != EOF) {

      if (c == '\n') continue;
      if (c != '#') {   
         ungetc(c, fp);
         if (fscanf(fp, "%s %s", key, val) < 0)
            die("configuration file");
         debug_print("%s %s\n", key, val); 

         if (!strcmp(key, "udp-server-port")) 
            state->udp_port = strtol(val, NULL, 10);  
         else if (!strcmp(key, "tcp-server-port")) 
            state->tcp_port = strtol(val, NULL, 10);
         else if (!strcmp(key, "source-port")) 
            state->port = strtol(val, NULL, 10);
         else if (!strcmp(key, "private-address")) 
            state->private_addr = strdup(val);
         else if (!strcmp(key, "inactivity_timeout")) 
            state->inactivity_timeout = strtol(val, NULL, 10);
         else if (!strcmp(key, "tcp-send-timeout")) 
            state->tcp_snd_timeout = strtol(val, NULL, 10);
         else if (!strcmp(key, "tcp-receive-timeout")) 
            state->tcp_rcv_timeout = strtol(val, NULL, 10);
         else if (!strcmp(key, "client-file")) 
            state->cli_file = strdup(val);
         else if (!strcmp(key, "server-file")) 
            state->serv_file = strdup(val);
         else if (!strcmp(key, "buffer-length")) 
            state->buf_length = strtol(val, NULL, 10);
         else if (!strcmp(key, "backlog-size")) 
            state->backlog_size = strtol(val, NULL, 10);
         else if (!strcmp(key, "fd-lim")) 
            state->fd_lim = strtol(val, NULL, 10);
         
      } 
      /* dump rest of line */ 
      do {
         c =fgetc(fp);
      } while (c != EOF && c != '\n');
   }

   return 0;
}

int parse_dest_file(struct arguments *args, struct tun_state *state) {
   if (!args->dest_file) {
      errno=ENOENT;
      return -1;
   }

   /* <unique port> <public addr> <private addr> */
   FILE *fp = fopen(args->dest_file, "r");
   if(!fp) {
      errno=ENOENT;
      return -1;
   }

   int sport, count=0;
   char public[16], private[16];
   /* build port to public addr lookup table */
   while (fscanf(fp, "%d %s %s", &sport, public, private) == 3) {
      struct tun_rec *nrec = init_tun_rec();
      nrec->sa    = (struct sockaddr *)get_addr(public, state->udp_port);
      nrec->sport = sport;  
      nrec->priv_addr = inet_addr(private);
      if (!g_hash_table_insert(state->cli, &nrec->priv_addr, nrec)) {
         errno=EINVAL;//keys are not unique
         return -1;  
      }
      debug_print("%s:%d\n", public, sport);
      count++;
   }   
   rewind(fp);

   /* build destination list */
   state->cli_private = malloc(count * sizeof(struct tun_rec *));
   state->sa_len      = count;
   int i = 0;
   while (fscanf(fp, "%d %s %s", &sport, public, private) == 3) {
      struct tun_rec *nrec = init_tun_rec();
      nrec->sa    = (struct sockaddr *)get_addr(private, state->tcp_port);
      nrec->sport = sport;  

      state->cli_private[i++] = nrec;
   }

   return 0;
}

struct tun_state *init_tun_state(struct arguments *args) {
   struct tun_state *state = malloc(sizeof(struct tun_state));
   memset(state, 0, sizeof(struct tun_state));
   state->args = args;   
   if (parse_cfg_file(state) < 0)
      die("configuration file");

   switch (args->mode) {
      case FULLMESH_MODE:
         state->cli  = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, (GDestroyNotify) free_tun_rec);
         if (parse_dest_file(args, state) < 0)
            die("destination file");
      case SERV_MODE:
         state->serv = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, (GDestroyNotify) free_tun_rec);
      case CLI_MODE:
      default:
         break;
   }

   /* Replace cfg value with args */
   if (args->inactivity_timeout)
      state->inactivity_timeout = args->inactivity_timeout;

   init_destructors(state);
   
   return state;
}

void free_tun_state(struct tun_state *state) {
   free(state->private_addr);
   //free(state->public_addr);
   if (state->serv)
      g_hash_table_destroy(state->serv); 
   if (state->cli)
      g_hash_table_destroy(state->cli); 
   if (state->private_addr)
      free(state->private_addr);
   if (state->cli_file)
      free(state->cli_file);
   if (state->serv_file)
      free(state->serv_file);
   int i;
   for (i=0; i<state->sa_len; i++) 
      free_tun_rec(state->cli_private[i]);
   free(state->cli_private);
   free(state);
}

struct tun_rec *init_tun_rec() {
   struct tun_rec *ret = malloc(sizeof(struct tun_rec));
   ret->sa        = malloc(sizeof(struct sockaddr_in));
   ret->slen      = sizeof(struct sockaddr_in);
   ret->sport     = 0;
   ret->priv_addr = 0;

   return ret;
}

void free_tun_rec(struct tun_rec *rec) { 
   free(rec->sa);free(rec); 
}


