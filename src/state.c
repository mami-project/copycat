/**
 * \file state.c
 * \brief State-related features.
 *
 * \author k.edeline
 * \version 0.1
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "state.h"
#include "debug.h"
#include "udptun.h"
#include "destruct.h"
#include "net.h"
#include "xpcap.h"
#include "thread.h"

/**
 * \fn static int parse_dest_file4(struct arguments *args, struct tun_state *state)
 * \brief Parse destination file and file hash table with sockaddr's.
 *
 * \param args
 * \param state
 * \return 0 for success, -1 on error (errno is filled)
 */
static int parse_dest_file4(struct arguments *args, struct tun_state *state);

/**
 * \fn static int parse_dest_file(struct arguments *args, struct tun_state *state)
 * \brief Parse destination file and file hash table with sockaddr's.
 *
 * \param args
 * \param state
 * \return 0 for success, -1 on error (errno is filled)
 */
static int parse_dest_file(struct arguments *args, struct tun_state *state);

/**
 * \fn static int parse_cfg_file(struct tun_state *state)
 * \brief Parse configuration file 
 *
 * \param state
 * \return 0 for success, -1 on error (errno is filled)
 */
static int parse_cfg_file(struct tun_state *state);

/**
 * \fn static void free_tun_rec_aux(gpointer key,
 *                                  gpointer value,
 *                                  gpointer user_data)
 * \brief A stub for GLIB2 auto free
 *
 * \param key unused
 * \param value A pointer to a valid struct free_tun_rec
 * \param user_data unused
 */
static void free_tun_rec_aux(gpointer key,
                      gpointer value,
                      gpointer user_data);

static GHashTable *init_table(int v);

GHashTable *init_table(int v) {
   GHashTable *htable = NULL;
#if defined(GLIB2)
   //htable = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, 
   //                              (GDestroyNotify) free_tun_rec);
   //XXX: g_hash_table_new_full does not work with duplicated data
   htable = g_hash_table_new(g_int_hash, (v==4) ? g_int_equal : g_str_equal);
#elif defined(GLIB1)
   htable = g_hash_table_new(g_int_hash, (v==4) ? g_int_equal : g_str_equal);
#endif
   return htable;
}

struct tun_state *init_tun_state(struct arguments *args) {
   struct tun_state *state = calloc(1, sizeof(struct tun_state));
   state->args = args;   
   if (parse_cfg_file(state) < 0)
      die("configuration file");

   /* create htables */
   if (args->mode == SERV_MODE || args->mode == FULLMESH_MODE) {
      state->serv = init_table(4);
   }
   if (args->mode == CLI_MODE || args->mode == FULLMESH_MODE) {
       state->cli4 = init_table(4);

      if (args->ipv6 || args->dual_stack) {
         state->cli6 = init_table(6);
         if (parse_dest_file(args, state) < 0)
            die("destination file");
      } else {
         if (parse_dest_file4(args, state) < 0)
            die("destination file");
      }
   }

   /* Replace cfg value with args */
   if (args->inactivity_timeout)
      state->inactivity_timeout = args->inactivity_timeout;
   if (args->planetlab)
      state->planetlab = 1;
   if (args->freebsd)
      state->freebsd = 1;
   if (args->ipv6)
      state->ipv6 = 1;
   if (args->dual_stack)
      state->dual_stack = 1; 

   /* File locations */
   state->cli_file_tun4   = xmalloc(STR_SIZE);
   state->cli_file_notun4 = xmalloc(STR_SIZE);
   state->cli_file_tun6   = xmalloc(STR_SIZE);
   state->cli_file_notun6 = xmalloc(STR_SIZE);
   strncpy(state->cli_file_tun4, state->cli_dir, STR_SIZE);
   strncpy(state->cli_file_notun4, state->cli_dir, STR_SIZE);
   strncat(state->cli_file_tun4, CLI_TUN_FILE4, STR_SIZE);
   strncat(state->cli_file_notun4, CLI_NOTUN_FILE4, STR_SIZE);
   strncpy(state->cli_file_tun6, state->cli_dir, STR_SIZE);
   strncpy(state->cli_file_notun6, state->cli_dir, STR_SIZE);
   strncat(state->cli_file_tun6, CLI_TUN_FILE6, STR_SIZE);
   strncat(state->cli_file_notun6, CLI_NOTUN_FILE6, STR_SIZE);

   /* init network settings */
   if (args->ipv6)
      state->default_if = addr_to_itf6(state->public_addr6);
   else
      state->default_if = addr_to_itf4(state->public_addr4);
   
   /* init synchronizer and garbage collector */
   init_barrier(2);
   init_destructors(state);

   return state;
}

void free_tun_state(struct tun_state *state) {

#if defined(GLIB1)
#endif
   /* Free HTables (GLIB 1 && GLIB 2 < 2.12)  */
   if (state->serv) 
      g_hash_table_foreach (state->serv, 
                            (GHFunc) free_tun_rec_aux,
                            NULL);
   if (state->cli4) 
      g_hash_table_foreach (state->cli4, 
                            (GHFunc) free_tun_rec_aux,
                            NULL);
   /*if (state->cli6) 
      g_hash_table_foreach (state->cli6, 
                            (GHFunc) free_tun_rec_aux,
                            NULL);*/
//#endif
   if (state->serv) 
      g_hash_table_destroy(state->serv); 
   if (state->cli4)
      g_hash_table_destroy(state->cli4); 
   if (state->cli6)
      g_hash_table_destroy(state->cli6);

   /* Free mallocs */
   if (state->private_addr4)
      free(state->private_addr4);
   if (state->private_mask4)
      free(state->private_mask4);
   if (state->private_addr6)
      free(state->private_addr6);
   if (state->private_mask6)
      free(state->private_mask6);
   if (state->public_addr4)
      free(state->public_addr4);
   if (state->public_addr6)
      free(state->public_addr6);
   if (state->cli_dir)
      free(state->cli_dir);
   if (state->serv_file)
      free(state->serv_file);
   if (state->tun_if)
      free(state->tun_if);
   if (state->default_if)
      free(state->default_if);
   if (state->cli_file_tun4)
      free(state->cli_file_tun4);
   if (state->cli_file_notun4)
      free(state->cli_file_notun4);
   if (state->cli_file_tun6)
      free(state->cli_file_tun6);
   if (state->cli_file_notun6)
      free(state->cli_file_notun6);
   if (state->out_dir)
      free(state->out_dir);

   /* Free tun_rec's */
   if (state->cli_private) {
      int i;
      for (i=0; i<state->sa_len; i++) 
         free_tun_rec(state->cli_private[i]);
      free(state->cli_private);
   }
   if (state->cli_public) {
      int i;
      for (i=0; i<state->sa_len; i++) 
         free_tun_rec(state->cli_public[i]);
      free(state->cli_public);
   }
   free(state);

   destroy_barrier();
}

struct tun_rec *init_tun_rec(struct tun_state *state) {
   struct tun_rec *ret = calloc(1, sizeof(struct tun_rec));

   /* IPv4 sockaddr */
   if (state->dual_stack || !state->ipv6) {
      ret->sa4        = xmalloc(sizeof(struct sockaddr_in));
      ret->slen4      = sizeof(struct sockaddr_in);
   } else {
      ret->sa4 = NULL;
      ret->slen4 = 0;
   }

   /* IPv6 sockaddr */
   if (state->dual_stack || state->ipv6) {
      ret->sa6        = xmalloc(sizeof(struct sockaddr_in6));
      ret->slen6      = sizeof(struct sockaddr_in6);
   } else {
      ret->sa6 = NULL;
      ret->slen6 = 0;
   }

   return ret;
}

void free_tun_rec_aux(gpointer UNUSED(key),
                      gpointer value,
                      gpointer UNUSED(user_data)) { 
   free_tun_rec((struct tun_rec *)value); 
}

void free_tun_rec(struct tun_rec *rec) { 
   if (rec->sa4) free(rec->sa4);
   if (rec->sa6) free(rec->sa6);
   if (rec) free(rec); 
}

int parse_cfg_file(struct tun_state *state) {
   FILE *fp = fopen(state->args->config_file, "r");
   if(!fp) {
      errno=ENOENT;
      return -1;
   }

   char key[256], val[256], c;
   /* build port to public addr lookup table */
   while ((c =fgetc(fp)) != EOF) {

      if (c == '\n') continue;
      if (c != '#') {   
         ungetc(c, fp);
         if (fscanf(fp, "%s %s", key, val) < 0)
            die("configuration file");
         debug_print("%s %s\n", key, val); 
         /* networking parameters */
         if (!strcmp(key, "public-server-port")) 
            state->public_port = strtol(val, NULL, 10);  
         else if (!strcmp(key, "private-server-port")) 
            state->private_port = strtol(val, NULL, 10);
         else if (!strcmp(key, "source-port")) 
            state->port = strtol(val, NULL, 10);
         else if (!strcmp(key, "private-address4")) 
            state->private_addr4 = strdup(val);
         else if (!strcmp(key, "private-mask4")) 
            state->private_mask4 = strdup(val);
         else if (!strcmp(key, "private-address6")) 
            state->private_addr6 = strdup(val);
         else if (!strcmp(key, "private-mask6")) 
            state->private_mask6 = strdup(val);
         else if (!strcmp(key, "public-address4")) 
            state->public_addr4  = strdup(val);
         else if (!strcmp(key, "public-address6")) 
            state->public_addr6 = strdup(val);
         /* timeouts */
         else if (!strcmp(key, "inactivity-timeout")) 
            state->inactivity_timeout = strtol(val, NULL, 10);
         else if (!strcmp(key, "initial-sleep")) 
            state->initial_sleep = strtol(val, NULL, 10);
         else if (!strcmp(key, "tcp-send-timeout")) 
            state->tcp_snd_timeout = strtol(val, NULL, 10);
         else if (!strcmp(key, "tcp-receive-timeout")) 
            state->tcp_rcv_timeout = strtol(val, NULL, 10);
         /* locations & dirs */
         else if (!strcmp(key, "client-dir")) 
            state->cli_dir = strdup(val);
         else if (!strcmp(key, "output-dir")) 
            state->out_dir = strdup(val);
         else if (!strcmp(key, "server-file")) 
            state->serv_file = strdup(val);
         /* system settings */
         else if (!strcmp(key, "buffer-length")) 
            state->buf_length = strtol(val, NULL, 10);
         else if (!strcmp(key, "backlog-size")) 
            state->backlog_size = strtol(val, NULL, 10);
         else if (!strcmp(key, "fd-lim")) 
            state->fd_lim = strtol(val, NULL, 10);
         else if (!strcmp(key, "tun-tcp-mss")) 
            state->max_segment_size = strtol(val, NULL, 10);
         /* interfaces */
         else if (!strcmp(key, "tun-if")) 
            state->tun_if = strdup(val);
      
         /* NOTE: add cfg parameters here */
      } 
      /* dump rest of line */ 
      do {
         c =fgetc(fp);
      } while (c != EOF && c != '\n');
   }

   fclose(fp);
   return 0;
}

int parse_dest_file(struct arguments *args, struct tun_state *state) {
   if (!args->dest_file) {
      errno=ENOENT;
      return -1;
   }

   /*<unique port> <public addr4> <private addr4> <public addr6> <private addr6> */
   FILE *fp = fopen(args->dest_file, "r");
   if(!fp) {
      errno=ENOENT;
      return -1;
   }

   int sport, count=0;
   char public4[INET_ADDRSTRLEN], private4[INET_ADDRSTRLEN]; 
   char public6[INET6_ADDRSTRLEN], private6[INET6_ADDRSTRLEN];
   struct tun_rec *nrec_priv = NULL;
   /* build port to public addr lookup table */
   while (fscanf(fp, "%d %s %s %s %s", &sport, public4, private4, 
                                               public6, private6) == 5) {
      nrec_priv        = init_tun_rec(state);
      nrec_priv->sa4   = (struct sockaddr *)get_addr4(public4, state->public_port);
      nrec_priv->sa6   = (struct sockaddr *)get_addr6(public6, state->public_port);
      nrec_priv->sport = sport;  

      /* add to Htables by n-ordered addresses */
      if (!inet_pton(AF_INET, private4, &nrec_priv->priv_addr4))
         die("inet_pton");      
      if (!inet_pton(AF_INET6, private6, nrec_priv->priv_addr6))
         die("inet_pton");  
      g_hash_table_insert(state->cli4, &nrec_priv->priv_addr4, nrec_priv);
      g_hash_table_insert(state->cli6, nrec_priv->priv_addr6, nrec_priv);

      if (state->serv) {
         struct tun_rec *nrec_pub  = init_tun_rec(state);
         nrec_pub->sa4    = (struct sockaddr *)get_addr4(public4, sport);
         nrec_pub->sa6    = (struct sockaddr *)get_addr6(public6, sport);
         nrec_pub->sport = sport;  
         g_hash_table_insert(state->serv, &nrec_pub->sport, nrec_pub);
      }

      debug_print("%s:%d\n", public4, sport);
      debug_print("%s:%d\n", public6, sport);

      count++;
   }   
  
   /* browse twice because of array malloc */
   rewind(fp);

   /* build destination list */
   state->cli_private = xmalloc(count * sizeof(struct tun_rec *));
   state->cli_public  = xmalloc(count * sizeof(struct tun_rec *));
   state->sa_len      = count;
   int i = 0, ret; 
   while (fscanf(fp, "%d %s %s %s %s", &sport, public4, private4, 
                                               public6, private6) == 5) {
      struct tun_rec *nrec_priv = init_tun_rec(state);
      struct tun_rec *nrec_pub  = init_tun_rec(state);

      /* add private sockaddr */
      nrec_priv->sa4    = (struct sockaddr *)get_addr4(private4, state->private_port);
      nrec_priv->sa6    = (struct sockaddr *)get_addr6(private6, state->private_port);
      nrec_priv->sport = sport;  
      state->cli_private[i] = nrec_priv;

      /* add public sockaddr */
      nrec_pub->sa4    = (struct sockaddr *)get_addr4(public4, state->public_port);
      nrec_pub->sa6    = (struct sockaddr *)get_addr6(public6, state->public_port);
      nrec_pub->sport = sport;  
      state->cli_public[i++] = nrec_pub;
   }
   
   fclose(fp);

   return 0;
}

int parse_dest_file4(struct arguments *args, struct tun_state *state) {
   if (!args->dest_file) {
      errno=ENOENT;
      return -1;
   }

   /** 
    * IPv4: <unique port> <public addr> <private addr> 
    * IPv6: <unique port> <public addr> <private addr> 
    * both: <unique port> <public addr4> <private addr4> <public addr6> <private addr6> 
    */
   FILE *fp = fopen(args->dest_file, "r");
   if(!fp) {
      errno=ENOENT;
      return -1;
   }

   int sport, count=0;
   char public[INET_ADDRSTRLEN], private[INET_ADDRSTRLEN];
   /* build port to public addr lookup table */
   while (fscanf(fp, "%d %s %s", &sport, public, private) == 3) {
      struct tun_rec *nrec_priv = init_tun_rec(state);
      nrec_priv->sa4   = (struct sockaddr *)get_addr4(public, state->public_port);
      nrec_priv->sport = sport;  
      if (!inet_pton(AF_INET, private, &nrec_priv->priv_addr4))
         die("inet_pton");
      g_hash_table_insert(state->cli4, &nrec_priv->priv_addr4, nrec_priv);
      debug_print("%s:%d\n", public, sport);

      if (state->serv) {
         struct tun_rec *nrec_pub  = init_tun_rec(state);
         nrec_pub->sa4   = (struct sockaddr *)get_addr4(public, sport);
         nrec_pub->sport = sport;  
         g_hash_table_insert(state->serv, &nrec_pub->sport, nrec_pub);
      }
      count++;
   }   
  
   /* browse twice because of array malloc */
   rewind(fp);

   /* build destination list */
   state->cli_private = xmalloc(count * sizeof(struct tun_rec *));
   state->cli_public  = xmalloc(count * sizeof(struct tun_rec *));
   state->sa_len      = count;
   int i = 0, ret; 
   while ( (ret = fscanf(fp, "%d %s %s", &sport, public, private)) == 3) {
      struct tun_rec *nrec_priv = init_tun_rec(state);
      struct tun_rec *nrec_pub  = init_tun_rec(state);

      /* add private sockaddr */
      nrec_priv->sa4   = (struct sockaddr *)get_addr4(private, state->private_port);
      nrec_priv->sport = sport;  
      state->cli_private[i] = nrec_priv;

      /* add public sockaddr */
      nrec_pub->sa4   = (struct sockaddr *)get_addr4(public, state->public_port);
      nrec_pub->sport = sport;  
      state->cli_public[i++] = nrec_pub;
   }
   
   fclose(fp);

   return 0;
}

