/**
 * \file xpcap.c
 * \brief libpcap wrappers
 * \author k.edeline
 * \version 0.1
 */

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>

#include "debug.h"
#include "sock.h"
#include "xpcap.h"
#include "state.h"
#include "udptun.h"

/**
 * \var pthread_barrier_t barr
 * \brief The synchronization barrier.
 */
pthread_barrier_t barr;

/**
 * \fn static void *term_capture(void* arg)
 * \brief Flush & properly close pcap dump buffers.
 *
 * \param arg pcap_t handle
 */ 
static void *term_capture(void* arg);

/**
 * \fn static void capture(char *dev, const char *addr, int port, char *filename)
 * \brief pcap sniff & dump process
 *
 * \param dev The network interface to sniff on
 * \param addr The address of this itf
 * \param port 
 * \param filename The location of the trace dump file
 */ 
static void capture(char *dev, const char *addr, int port, char *filename);

void *term_capture(void* arg) {
   pcap_t *handle = (pcap_t *)arg;
   pcap_breakloop(handle);
   pcap_close(handle);
   debug_print("closing pcap dump process...\n");
   return 0;
}

void init_barrier(int nthreads) {
   pthread_barrier_init(&barr, NULL, nthreads);
   debug_print("barrier initialized with %d threads\n", nthreads);
}

void destroy_barrier() {
   pthread_barrier_destroy(&barr);
}

void synchronize() {
   int ret = pthread_barrier_wait(&barr);
   if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) 
      die("pthread_barrier_wait");
}

void *capture_tun(void *arg) {
   struct tun_state *state = (struct tun_state *)arg;
   struct arguments* args  = state->args;
   char file_loc[512];

   strncpy(file_loc, state->out_dir, 512);   
   strncat(file_loc, "tun", 512);
   if (args->run_id) {
      strncat(file_loc, ".", 512);
      strncat(file_loc, args->run_id, 256);
   }
   strncat(file_loc, ".pcap", 512);
   debug_print("%s\n", file_loc);
   capture(state->if_name, state->private_addr, 0, file_loc);
   return 0;
}

void *capture_notun(void *arg) {
   struct tun_state *state = (struct tun_state *)arg;
   struct arguments* args  = state->args;
   char file_loc[512];

   strncpy(file_loc, state->out_dir, 512);   
   strncat(file_loc, "notun", 512);
   if (args->run_id) {
      strncat(file_loc, ".", 512);
      strncat(file_loc, args->run_id, 256);
   }
   strncat(file_loc, ".pcap", 512);
   debug_print("%s\n", file_loc);
   capture(state->default_if, state->public_addr, state->public_port, file_loc);
   return 0;
}

void capture(char *dev, const char *addr, int port, char *filename) {
	pcap_t *handle;
   char errbuf[PCAP_ERRBUF_SIZE];
	if ( (handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) 
	   die("pcap_open_live");

   /* build filter */
   char filter_exp[64];
   struct bpf_program fp;	
   bpf_u_int32 net = inet_addr(addr);

   if (port<0)
      sprintf(filter_exp, "not port %d or icmp", -port);
   else if (port>0)
      sprintf(filter_exp, "port %d or icmp", port);

   if (port) {  
      if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
         die("pcap_compile");
      if (pcap_setfilter(handle, &fp) == -1) 
         die("pcap_setfilter");
   }

   /* init pcap trace */
   pcap_dumper_t * dumper = pcap_dump_open(handle, filename);
   mode_t m = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
   if (chmod(filename, m) < 0)
      die("chmod");

   /* capture & dump */
   pthread_cleanup_push(term_capture, handle);
   synchronize();
	pcap_loop(handle, -1, pcap_dump, (void*) dumper);
   pthread_cleanup_pop(0);
}

struct sock_fprog *gen_bpf(const char *dev, const char *addr, int sport, int dport) {
   pcap_t *handle;		
   char errbuf[PCAP_ERRBUF_SIZE];	
   struct bpf_program *fp= malloc(sizeof(struct bpf_program));

   /* build filter */
   char filter_exp[64]; 
   if (sport && dport)
      sprintf(filter_exp, "src port %d and dst port %d", sport, dport);
   else if (sport && !dport)
      sprintf(filter_exp, "src port %d", sport);
   else if (!sport && dport)
      sprintf(filter_exp, "dst port %d", dport);

   /* compile filter */
   bpf_u_int32 net = inet_addr(addr);
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (!handle) 
      die( "Couldn't open device %s: %s");
   if (pcap_compile(handle, fp, filter_exp, 0, net) == -1) 
      die("Couldn't parse filter %s: %s\n");

   return (struct sock_fprog *)fp;
}

