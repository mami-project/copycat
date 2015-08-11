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
static void tun_serv_in(int fd_udp, int fd_raw, struct tun_serv_state *state, char *buf);
static int tun_serv_out(int fd_udp, struct arguments *args, struct tun_serv_state *state, char *buf);
static void build_sel(fd_set *input_set, int len, int *fds_raw, int *max_fd_raw);
static struct tun_serv_state *init_tun_serv(struct arguments *args);
static void free_tun_serv(struct tun_serv_state *state);
static struct tun_rec *init_tun_rec();
static void free_tun_rec(struct tun_rec *rec);

struct tun_rec {
   struct sockaddr *sa;
   unsigned int slen; 
   int sport;  // udp sport
   int fd; // raw sock fd
};

struct tun_serv_state {
   GHashTable *sport;
   GHashTable *fds;
   char *if_name;

   /* tcp endpoint sa */
   struct sockaddr *tcp_sa;
   int tcp_slen;

};

void int_handler(int sig) { loop = 0; }

/*
 *
 *
 */
void tun_serv_in(int fd_udp, int fd_raw, struct tun_serv_state *state, char *buf) {

   int recv_s=xrecv(fd_raw, buf, __BUFFSIZE);

#ifdef __DEBUG
   //todo change dport to args->ndport
   printf ("recvd %db from RAW\n", recv_s);
   for (int i=0;i<recv_s;i++) {
      printf("%x ",buf[i]);
      if (!((i+1)%16)) printf("\n"); 
   }
   printf("\n");  
   if (recv_s == 0) fprintf(stderr,"RECVFROM UDP RETURNED 0\n");
#endif

   if (recv_s > 0) {
      struct tun_rec *rec = NULL;
      if ( (rec = g_hash_table_lookup(state->fds, &fd_raw)) ) {   
         xsendto(fd_udp, (struct sockaddr_in *)rec->sa, buf, recv_s);
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
int tun_serv_out(int fd_udp, struct arguments *args, struct tun_serv_state *state, char *buf) {
   //TODO:free bpfs
   struct tun_rec *nrec = init_tun_rec();
   int ret = 0;
   int recv_s=xrecvfrom(fd_udp, buf, __BUFFSIZE, (struct sockaddr *)nrec->sa, &nrec->slen);

#ifdef __DEBUG
   //todo change dport to args->ndport
   printf ("recvd %db from udp\n", recv_s);
   for (int i=0;i<recv_s;i++) {
      printf("%x ",buf[i]);
      if (!((i+1)%16)) printf("\n"); 
   }
   printf("\n");  

   if (recv_s == 0) fprintf(stderr,"RECVFROM UDP RETURNED 0\n");
#endif

   if (recv_s > 0) {
      struct tun_rec *rec = NULL;
      int sport           = ntohs(((struct sockaddr_in *)nrec->sa)->sin_port);

      if ( (rec = g_hash_table_lookup(state->sport, &sport)) ) {
         //forward via fd from record
         xsendto(rec->fd, (struct sockaddr_in *)state->tcp_sa, buf, recv_s);

         free_tun_rec(nrec);
      } else if (g_hash_table_size(state->sport) <= UDP_TUN_FDLIM) { //add new record to lookup tables  

         // else: open new raw sock+bpf and update 
         struct sock_fprog *bpf = gen_bpf(state->if_name, args->tcp_daddr, args->tcp_dport, sport);
         int fd_raw = raw_tcp_sock(NULL, sport, bpf);

         xsendto(fd_raw, (struct sockaddr_in *)state->tcp_sa, buf, recv_s); // TODO:maybe wait ?

         nrec->sport = sport;
         nrec->fd    = fd_raw;
         ret         = fd_raw;

         g_hash_table_insert(state->sport, &nrec->sport, nrec);
         g_hash_table_insert(state->fds, &nrec->fd, nrec);
      } else {
         errno=EUSERS; //TODO no need to exit 
         die("socket()");
      }

   }

   return ret;
}

void tun_serv(struct arguments *args) {
   /*
    * ./udptun -s --udp-lport=5001 --tcp-daddr=192.168.2.1 --tcp-lport=9876
    *
    */
   int fd_max = 0, fd_udp = 0, sel = 0, i = 0;

   //init tun itf
   const char *prefix = "24";
   //TODO: si ça fonctionne sur une seule addr, init tun à part (autre argument)
   char *if_name  = create_tun(args->tcp_daddr, prefix, 0);
   //udp sock & dst sockaddr
   fd_udp   = udp_sock(args->udp_lport);

   struct tun_serv_state *state = init_tun_serv(args);
   state->if_name = strdup(if_name);


   //udp_addr = get_addr(args->udp_daddr, args->udp_dport);//TODO map de sport:sockaddr avec recvfrom
   //raw tcp sock with tcp dport bpf
   //bpf      = gen_bpf(if_name, args->tcp_daddr, 0, args->tcp_dport); //TODO: 0 by mapped port
   //raw sock & dst sockaddr
   //fd_raw   = raw_tcp_sock(args->tcp_daddr, 0, bpf); //TODO: 0 by mapped port


   int fds_raw[UDP_TUN_FDLIM];
   int fds_raw_len = 0, new_fd = 0;
   memset(fds_raw, 0, sizeof(fds_raw));

   fd_set input_set;
   struct timeval tv;
   char buf[__BUFFSIZE];

   loop=1;
   signal(SIGINT, int_handler);

   while (loop) {
      //build select args
      build_sel(&input_set, fds_raw_len, fds_raw, &fd_max);
      FD_SET(fd_udp, &input_set);
      fd_max=max(fd_max,fd_udp);
      tv.tv_sec  = 1;
      tv.tv_usec = 0;

      sel = select(fd_max+1, &input_set, NULL, NULL, &tv);
      if (sel < 0) die("select");
      else if (sel > 0) {
         if (FD_ISSET(fd_udp, &input_set)) {
            new_fd = tun_serv_out(fd_udp, args, state, buf);
            if (new_fd) fds_raw[fds_raw_len++] = new_fd;
         }

         for (i=0; i<fds_raw_len; i++) {
            if (FD_ISSET(fds_raw[i], &input_set)) {
              tun_serv_in(fd_udp, fds_raw[i], state, buf);
            }
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
   state->fds      = g_hash_table_new(g_int_hash, g_int_equal);

   state->tcp_sa   = (struct sockaddr *)get_addr(args->tcp_daddr, args->tcp_dport);
   state->tcp_slen = sizeof(struct sockaddr);

   return state;
}

void free_tun_serv(struct tun_serv_state *state) {
   g_hash_table_destroy(state->sport); //g_hash_table_foreach_remove
   g_hash_table_destroy(state->fds); //g_hash_table_foreach_remove   
   free(state->if_name);
   free(state);
}

struct tun_rec *init_tun_rec() {
   struct tun_rec *ret = malloc(sizeof(struct tun_rec));
   ret->sa     = malloc(sizeof(struct sockaddr_in));
   ret->slen   = sizeof(struct sockaddr_in);
   ret->sport  = 0;
   ret->fd = 0;

   return ret;
}

void free_tun_rec(struct tun_rec *rec) { free(rec->sa);free(rec); }
