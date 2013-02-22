/*
  frel.c

  network IDS evasion toolkit.

  Original fragrouter code by Dug Song
  Hax by lorg0r <lorgor@yahoo.com>

  Copyright (c) 1999 Anzen Computing. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. All advertising materials mentioning features or use of this software
     must display the following acknowledgement:
     This product includes software developed by Anzen Computing.
  4. Neither the name of Anzen Computing nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  
  $Id: stel.c,v 1.20 2001/01/13 22:36:51 asdfg Exp $
*/

#include "config.h"

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif
#ifdef HAVE_UNISTD_H
#include <sys/types.h>
#include <unistd.h>
#endif

#include <libnet.h>
#include "frel.h"
#include "ip_frag.h"
#include "sniff.h"
#include "send.h"
#include "attack.h"
#include "version.h"
#include "wrappers.h"


/* Definition of external variables */

int
    verbose = NOTVERBOSE,		/* output control */
    mode = MODE_RTEORIG;		/* default to original fragrouter opn */

struct libnet_link_int *llif = NULL;	/* Libnet interface structure */
int ll_len = 0;				/* Offset in packet to IP header */
char *dev = NULL;			/* Ascii name of device */

u_char *snd_llmac;			/* Our Ethernet MAC addr */
u_char *rtr_llmac;			/* Lan rtr's Ethernet MAC addr */
u_char *tovr_llmac;			/* Takeover machine's Ethernet MAC addr */
u_char *snf_llmac;			/* Dummy MAC addr for sniffing */

struct libnet_plist_chain plist;	/* Libnet port list chain */ 
struct libnet_plist_chain *plist_p = NULL;	/* Libnet port list chain pointer */ 


void
usage(void)
{
  int i;
  char *str;
  
  fprintf(stderr, "\nFrel version " FREL_VERSION "\n"
      "Usage: frel [-i interface] [-pv] [-g hop] [-G hopcount] -u `nnn,nnn-nnn` \n"
      " [-s xx:xx:xx:xx:xx:xx]  [-r xx:xx:xx:xx:xx:xx]  [-t xx:xx:xx:xx:xx:xx] -m mode ATTACK\n\n"
      " where -m specifies mode of operation: \n"
      "               1    original fragrouter\n"
      "               2    fragproxy runs on same machine\n"
      "               3    partial takeover of real machine on same subnet\n\n"
      "       -s specifies ethernet mac address to sniff on\n"
      "       -r    ...    subnet router mac addr\n"
      "       -t    ...    takeover host mac addr\n"
      "       -u    ...    port list for takeover\n\n"
      "       ATTACK is one of the following:\n\n");

  for (i = 1; i < 10; i++)
    if ((str = attack_string(ATTACK_BASE, i)) != NULL)
      fprintf(stderr, " -B%d: %s\n", i, str);

  for (i = 1; i < 10; i++)
    if ((str = attack_string(ATTACK_FRAG, i)) != NULL)
      fprintf(stderr, " -F%d: %s\n", i, str);
  
  for (i = 1; i < 10; i++)
    if ((str = attack_string(ATTACK_TCP, i)) != NULL)
      fprintf(stderr, " -T%d: %s\n", i, str);
  
  for (i = 1; i < 10; i++)
    if ((str = attack_string(ATTACK_TCBC, i)) != NULL)
      fprintf(stderr, " -C%d: %s\n", i, str);
  
  for (i = 1; i < 10; i++)
    if ((str = attack_string(ATTACK_TCBT, i)) != NULL)
      fprintf(stderr, " -R%d: %s\n", i, str);

  for (i = 1; i < 10; i++)
    if ((str = attack_string(ATTACK_INSERT, i)) != NULL)
      fprintf(stderr, " -I%d: %s\n", i, str);

  for (i = 1; i < 10; i++)
    if ((str = attack_string(ATTACK_EVADE, i)) != NULL)
      fprintf(stderr, " -E%d: %s\n", i, str);

  for (i = 1; i < 10; i++)
    if ((str = attack_string(ATTACK_MISC, i)) != NULL)
      fprintf(stderr, " -M%d: %s\n", i, str);
  
  fprintf(stderr, "\n");
  exit(1);
}

int
main(int argc, char *argv[]) {

  char c,
    ebuf[BUFSIZ],			/* Buffer for error messages */
    hops[BUFSIZ];			/* For LSRR hops */
  int num = 0,				/* number for sub-attack */
    type = -1,				/* type of attack */
    hopptr = 4;				/* LSRR hop ptr */
  attack_handler attack;
  char ethersniff[ETHER_INPUT_LEN+1];	/* ethernet mac addr to sniff on */
  int err_flag = FALSE;
  char prt_tmp[ETHER_INPUT_LEN+1];
  
  hops[0] = '\0';
  ethersniff[0] = '\0';

  /* allocate space for mac addr */

  if (!(snd_llmac = malloc(ETHER_ADDR_LEN))){
    perror("Insufficient memory");
    err_flag = TRUE;
  }
  if (!(rtr_llmac = malloc(ETHER_ADDR_LEN))){
    perror("Insufficient memory");
    err_flag = TRUE;
  }
  if (!(snf_llmac = malloc(ETHER_ADDR_LEN))){
    perror("Insufficient memory");
    err_flag = TRUE;
  }
  if (!(tovr_llmac = malloc(ETHER_ADDR_LEN))){
    perror("Insufficient memory");
    err_flag = TRUE;
  }

  
  while ((c = getopt(argc, argv, "B:F:T:C:R:I:E:M:i:g:G:pvm:r:s:t:u:Vh")) != EOF) {
    switch (c) {
    case 'B':
      type = ATTACK_BASE;
      num = atoi(optarg);
      break;
    case 'F':
      type = ATTACK_FRAG;
      num = atoi(optarg);
      break;
    case 'T':
      type = ATTACK_TCP;
      num = atoi(optarg);
      break;
    case 'C':
      type = ATTACK_TCBC;
      num = atoi(optarg);
      break;
    case 'R':
      type = ATTACK_TCBT;
      num = atoi(optarg);
      break;
    case 'I':
      type = ATTACK_INSERT;
      num = atoi(optarg);
      break;
    case 'E':
      type = ATTACK_EVADE;
      num = atoi(optarg);
      break;
    case 'M':
      type = ATTACK_MISC;
      num = atoi(optarg);
      break;
    case 'p':				/* Preserve protocol header */
      ip_frag_init(1);
      break;
    case 'g':				/* Specify hop along LSRR route */
      strcat(hops, optarg);
      strcat(hops, " ");
      break;
    case 'G':				/* Position hop counter */
      hopptr = atoi(optarg);
      break;
    case 'i':				/* Interface to bind to for packet generation */
      dev = strdup(optarg);
      break;
    case 's':				/* Dummy Ethernet mac addr to sniff on */
      strcpy( ethersniff, optarg);
      memcpy(snf_llmac, (u_char *)frel_ether_aton( optarg ), ETHER_ADDR_LEN);
      break;
    case 'r':				/* Lan rtr's Ethernet */
      memcpy(rtr_llmac, (u_char *)frel_ether_aton( optarg ), 6);
      break;
    case 't':				/* Takeover machine's Ethernet mac addr */
      memcpy(tovr_llmac, (u_char *)frel_ether_aton( optarg ), ETHER_ADDR_LEN);
      break;
    case 'm':				/* Mode of operation */
      mode = atoi(optarg);
      break;
    case 'u':
      plist_p = &plist; 
      if (libnet_plist_chain_new(&plist_p, optarg) == -1) { 
	fprintf(stderr, "frel: Could not build port list\n"); 
	err_flag = TRUE;
	} 
      break; 
    case 'v':				/* Increase verbosity of output */
      if (verbose < VERYVERBOSE)
	verbose ++;
      break;
    default:
      usage();
    }
  }

  /* Check input arguments for validity */

  argc -= optind;
  argv += optind;
  
  if (argc != 0 || type == -1) {
    fprintf(stderr, "frel: Unknown parameter\n");
    err_flag = TRUE;
  }

  if (type == -1) {
    fprintf(stderr, "frel: Must specify at least one type of attack\n");
    err_flag = TRUE;
  }
 
  switch( mode ) {

  case MODE_RTEORIG:
    if ((verbose >= VERBOSE) && !err_flag) 
      printf("frel: Mode of operation - vanilla fragrouter\n\n");
    break;

  case MODE_RTESAME:

    if ( strlen( ethersniff ) != ( ETHER_INPUT_LEN) ) {
      fprintf(stderr, "frel: Must use -s to specify mac address for sniffing.\n");
      err_flag = TRUE;
    }
    if (!memcmp(rtr_llmac, snd_llmac, ETHER_ADDR_LEN) ) {
      fprintf(stderr, "frel: Must use -r to specify mac address of Lan rtr.\n");
      err_flag = TRUE;
    }
    if ((verbose >= VERBOSE) && !err_flag) {
      printf("frel: Mode of operation - fragproxy on same machine \n"
	     "      sniffing on %s, rtr mac is %s\n\n", ethersniff, frel_ether_ntoa( (struct ether_addr *)rtr_llmac ));
    }
    break;

  case MODE_TAKEOVER:
    if (!memcmp(rtr_llmac, snd_llmac, ETHER_ADDR_LEN)) {
      fprintf(stderr, "frel: Must use -r to specify mac addr of Lan rtr.\n");
      err_flag = TRUE;
    }
    if (!memcmp(tovr_llmac, snd_llmac, ETHER_ADDR_LEN)) {
      fprintf(stderr, "frel: Must use -t to specify mac addr of machine to takeover.\n");
      err_flag = TRUE;
    }
    if ( strlen( ethersniff ) != ( ETHER_INPUT_LEN) ) {
      fprintf(stderr, "frel: Must use -s to specify mac address for sniffing.\n");
      err_flag = TRUE;
    }
    if ( plist_p == NULL ) {
      fprintf(stderr, "frel: Must use -u to specify ports to intercept.\n");
      err_flag = TRUE;
    }

    strcpy(prt_tmp, frel_ether_ntoa((struct ether_addr *) tovr_llmac)); 
    if ((verbose >= VERBOSE) && !err_flag) {
      printf("frel: Mode of operation - partial takeover of machine at %s\n"
	     "      sniffing on %s, rtr mac is %s\n",
	     prt_tmp,
	     ethersniff,
	     frel_ether_ntoa((struct ether_addr *) rtr_llmac ));
      printf("      ports being intercepted: ");
      libnet_plist_chain_dump( plist_p );
    }
    break;

  default:
    fprintf(stderr, "frel: mode not implemented: %d\n", mode);
  }

  if (err_flag) {
    usage();
    exit(1);
  }


  /* Initialize the processing */

  if (!sniff_init(ebuf, ethersniff)) {
    fprintf(stderr, "frel: sniff_init failed: %s\n", ebuf);
    exit(1);
  }
  if (!send_init(ebuf, hops, hopptr)) {
    fprintf(stderr, "frel: send_init failed: %s\n", ebuf);
    exit(1);
  }
  if (!(attack = attack_init(type, num, ebuf))) {
    fprintf(stderr, "frel: attack_init failed: %s\n", ebuf);
    exit(1);
  }
  fprintf(stderr, "frel: %s\n", attack_string(type, num));
  
  sniff_loop(attack);

  exit(0);
}










