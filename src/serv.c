/*
 * serv.c: server
 * 
 *
 * @author k.edeline
 */

#include "serv.h"
#include <glib.h>

static volatile int loop;

struct tun_rec;
struct tun_serv_state;

static void int_handler(int sig);
static void tun_serv_in(int fd_udp, int fd_tun, struct tun_serv_state *state, char *buf);
static void tun_serv_out(int fd_udp, int fd_tun, struct arguments *args, struct tun_serv_state *state, char *buf);
static void build_sel(fd_set *input_set, int len, int *fds_raw, int *max_fd_raw);
static struct tun_serv_state *init_tun_serv(struct arguments *args);
static void free_tun_serv(struct tun_serv_state *state);
static struct tun_rec *init_tun_rec();
static void free_tun_rec(struct tun_rec *rec);

struct tun_rec {
   struct sockaddr *sa;
   unsigned int slen; 
   int sport;  // udp sport
};

struct tun_serv_state {
   GHashTable *sport;
   char *if_name;

   /* tcp endpoint sa */
   struct sockaddr *tcp_sa;
   unsigned int tcp_slen;

};

void int_handler(int sig) { loop = 0; }

/*
 *
 *
 */
void tun_serv_in(int fd_udp, int fd_tun, struct tun_serv_state *state, char *buf) {

   int recvd=xread(fd_tun, buf, __BUFFSIZE);

#ifdef __DEBUG
   fprintf (stderr,"serv: recvd %db from tun\n", recvd);
   //todo change dport to args->ndport
   if (recvd == 0) fprintf(stderr,"RECVFROM UDP RETURNED 0\n");
#endif

   if (recvd > 32) {

      struct tun_rec *rec = NULL; 
      //read sport for clients mapping
      int sport           =  (int) ntohs( *((uint16_t *)(buf+26)) );
      fprintf(stderr,"port is %d\n",sport);
      if ( (rec = g_hash_table_lookup(state->sport, &sport)) ) {   
#ifdef __DEBUG
         fprintf(stderr,"lookup: OK\n");
         if (recvd > 32) {
            fprintf(stderr,"ports %d %d\n",ntohs( *((uint16_t *)(buf+24)) ),
                                           ntohs( *((uint16_t *)(buf+26)) ));
         }
#endif

         int sent = xsendto(fd_udp, rec->sa, buf, recvd);
#ifdef __DEBUG
         fprintf(stderr,"serv: wrote %db to udp\n",sent);
#endif
      } else {
         errno=EFAULT;
         die("lookup");
      }
   }

}

/*
 *
 *
 */
void tun_serv_out(int fd_udp, int fd_tun, struct arguments *args, struct tun_serv_state *state, char *buf) {

   struct tun_rec *nrec = init_tun_rec();
   int recvd=xrecvfrom(fd_udp, (struct sockaddr *)nrec->sa, &nrec->slen, buf, __BUFFSIZE);

#ifdef __DEBUG
   fprintf (stderr,"serv: recvd %db from udp\n", recvd);
   //todo change dport to args->ndport
   if (recvd == 0) fprintf(stderr,"RECVFROM UDP RETURNED 0\n");
#endif

   if (recvd > 4) {
      fprintf(stderr,"frame: %2x %2x %2x %2x\n", buf[0], buf[1], buf[2], buf[3]);
      struct tun_rec *rec = NULL;
      int sport           = ntohs(((struct sockaddr_in *)nrec->sa)->sin_port);
      int sent            = 0;
      if ( (rec = g_hash_table_lookup(state->sport, &sport)) ) {
         //forward
         sent = xwrite(fd_tun, buf, recvd);
         free_tun_rec(nrec);
      } else if (g_hash_table_size(state->sport) <= UDP_TUN_FDLIM) { //add new record to lookup tables  
         sent = xwrite(fd_tun, buf, recvd);

         nrec->sport = sport;
         g_hash_table_insert(state->sport, &nrec->sport, nrec);

#ifdef __DEBUG  
         fprintf(stderr,"serv: added new entry: %d\n",sport);
#endif
      } else {
         errno=EUSERS; //TODO no need to exit but safer
         die("socket()");
      }
#ifdef __DEBUG
         fprintf(stderr,"serv: wrote %d to tun\n",sent);   
#endif
   
   }
}

void tun_serv(struct arguments *args) {
   /* e.g.
    * ./udptun -s --udp-lport=5001 --tcp-daddr=192.168.2.1 --tcp-dport=9876
    *
    */
   int fd_max = 0, fd_udp = 0, sel = 0, i = 0, fd_tun = 0;

   //init tun itf
   const char *prefix = "24";
   //TODO: init tun à part (autre argument) 
   char *if_name  = create_tun(args->tcp_daddr, prefix, 0, &fd_tun);
   //udp sock & dst sockaddr
   fd_udp   = udp_sock(args->udp_lport);

   struct tun_serv_state *state = init_tun_serv(args);
   state->if_name = strdup(if_name);

   fd_set input_set;
   struct timeval tv;
   char buf[__BUFFSIZE];

   loop=1;
   signal(SIGINT, int_handler);

   while (loop) {
      //build select args
      FD_ZERO(&input_set);
      FD_SET(fd_udp, &input_set);FD_SET(fd_tun, &input_set);
      fd_max=max(fd_tun,fd_udp);
      tv.tv_sec  = 1;
      tv.tv_usec = 0;

      sel = select(fd_max+1, &input_set, NULL, NULL, &tv);
      if (sel < 0) die("select");
      else if (sel > 0) {
         if (FD_ISSET(fd_udp, &input_set)) {
            tun_serv_out(fd_udp, fd_tun, args, state, buf);
         }
         if (FD_ISSET(fd_tun, &input_set)) {
            tun_serv_in(fd_udp, fd_tun, state, buf);
         }

      }
   }

   close(fd_udp);////TODO
   free_tun_serv(state);
   free(if_name);
}

/*
 * build fd_set from fds_raw and set max_fd_raw
 * 
 */
void build_sel(fd_set *input_set, int len, int *fds_raw, int *max_fd_raw) {
   int i = 0, max_fd = 0, fd = 0;
   FD_ZERO(input_set);
   for (;i<len;i++) {
      fd = fds_raw[i];
      if (fd) {
       FD_SET(fd, input_set);
       max_fd = max(fd,max_fd);
      } else break;
   }

   *max_fd_raw = max_fd;
}

struct tun_serv_state *init_tun_serv(struct arguments *args) {
   struct tun_serv_state *state = malloc(sizeof(struct tun_serv_state));
   memset(state, 0, sizeof(struct tun_serv_state));

   state->sport    = g_hash_table_new(g_int_hash, g_int_equal);

   state->tcp_sa   = (struct sockaddr *)get_addr(args->tcp_daddr, args->tcp_dport);
   state->tcp_slen = sizeof(struct sockaddr);

   return state;
}

void free_tun_serv(struct tun_serv_state *state) {
   g_hash_table_destroy(state->sport); //g_hash_table_foreach_remove  
   free(state->if_name);
   free(state);
}

struct tun_rec *init_tun_rec() {
   struct tun_rec *ret = malloc(sizeof(struct tun_rec));
   ret->sa     = malloc(sizeof(struct sockaddr_in));
   ret->slen   = sizeof(struct sockaddr_in);
   ret->sport  = 0;

   return ret;
}

void free_tun_rec(struct tun_rec *rec) { free(rec->sa);free(rec); }
