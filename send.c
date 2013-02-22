/*
  send.c

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

  $Id: send.c,v 1.10 2001/01/13 22:35:23 asdfg Exp $
*/

#include "config.h"

#ifdef STDC_HEADERS
#include <stdio.h>
#endif
#include <errno.h>
#include <libnet.h>
#include "print.h"
#include "send.h"
#include "frel.h"

static int raw_socket = -1;
static struct ipoption *sropt = NULL;
static int sroptlen = 0;
static u_char *snd_buf = NULL;			/* Libnet buffer for output packet */


int
send_init(char *ebuf,				/* For error msgs */
	  char *hops,				/* LSRR Hop string */
	  int hopptr				/* LSRR Hop ptr */
	  )
{
  u_char *p, *q, optdata[MAX_IPOPTLEN];
  int optlen;

  if (hops && hops[0] != '\0') {
    if ((sropt = malloc(sizeof(*sropt))) == NULL) {
      perror("send_init - malloc");
      return 0;
    }
    q = optdata;
    p = strtok(hops, " ");
    for (; q - optdata < MAX_IPOPTLEN && p != NULL; p = strtok(NULL, " ")) {
      *((u_long *)q) = libnet_name_resolve(p, 1);
      q += 4;
    }
    optlen = q - optdata;
    sroptlen = 3 + optlen;
    
    memcpy(sropt->ipopt_list + 3, optdata, optlen);

    *(sropt->ipopt_list) = 0x83; /* LSRR */
    *(sropt->ipopt_list + 1) = sroptlen;
    *(sropt->ipopt_list + 2) = hopptr;
  }
  
  /* Initialize output depending on mode of operation */

  switch( mode ) {
  case MODE_RTEORIG:
    raw_socket = libnet_open_raw_sock(IPPROTO_RAW);
    if (raw_socket == -1) {
      strcpy(ebuf, strerror(errno));
      return 0;
    }
    break;

  case MODE_RTESAME:
  case MODE_TAKEOVER:
    if (libnet_init_packet(LIBNET_MAX_PACKET, &snd_buf) == -1) {
      perror("send_init - libnet_init_packet");
      return 0;
    }
    break;
    

  default:			/* Shouldn't come here */
    strcpy(ebuf,"Internal error 30 in send.c");
    return(0);
  }
  

  return 1;
}

int
send_packet(u_char *pkt, 
	    int pktlen)
{
  static u_char opkt[IP_MAXPACKET];
  struct ip *iph = (struct ip *)pkt;
  
  /* Sanity checking. */
  if (pktlen < ntohs(iph->ip_len)) return 0;
  
  /* Insert LSRR option, if any. */
  if (sropt) {
    /* XXX - ugh, suk. */
    memcpy(opkt, pkt, pktlen);
    
    if (libnet_insert_ipo(sropt, sroptlen, opkt) == -1) {
      perror("send_packet: libnet_insert_ipo");
      return 0;
    }
    iph = (struct ip *)opkt;
    pkt = opkt;
  }
  pktlen = ntohs(iph->ip_len);


  /* Write packet depending on mode of operation */
  
  switch( mode ) {
  case MODE_RTEORIG:

    while (libnet_write_ip(raw_socket, pkt, pktlen) != pktlen) {
      perror("libnet_write_ip");
      printf("send_packet failed: ");
      print_ip(pkt, pktlen);
      printf("\n");
      return 0;
    }
    break;

  case MODE_RTESAME:
    if (!send_raw_packet(pkt, pktlen, snd_llmac, rtr_llmac))	/* Fwd on packet sniffed on dummy interface */
      return 0;    
      break;

  case MODE_TAKEOVER:
    if (!send_raw_packet(pkt, pktlen, snd_llmac, rtr_llmac))
      return 0;
    break;

  default:			/* Shouldn't come here */
    fprintf(stderr, "Internal error 40 in send.c\n");
    return(0);
  }


  /* Print tcpdump-style output. */

  if (verbose >= VERYVERBOSE) {
    print_ip(pkt, pktlen);
    printf("\n");
  }

  return 1;
}

int
send_list(ELEM *list)
{
  ELEM *f;
  
  for (f = list ; f != NULL ; f = f->next) {
    if (!send_packet(f->data, f->len))
      return 0;
  }
  return 1;
}

int
send_raw_packet(const u_char *pkt,
		const int pktlen,
		const u_char *esrc,
		const u_char *edst) {
  
  int c = 0;

  if (libnet_build_ethernet(edst,		/* Assemble pieces in buffer */ 
			    esrc, 
			    ETHERTYPE_IP, 
			    pkt, 
			    pktlen, 
			    snd_buf)
      == -1) {
    perror("send_packet - libnet_build_ethernet");
    return 0;
  }
  
  /* For link level interface have to calculate IP checksum */
  if (libnet_do_checksum(snd_buf + ETH_H, IPPROTO_IP, LIBNET_IP_H) == -1) 
    { 
      perror("send_packet - libnet_build_ethernet");
      return 0;
    }
  
  /* Write the packet to the interface */
  c = libnet_write_link_layer(llif, dev, snd_buf, pktlen+ll_len); 
  if (c < pktlen+ll_len) { 
      fprintf(stderr, "libnet_write_link_layer only wrote %d bytes\n", c); 
      return 0;
  } 
  else { 
      if (verbose >= VERYVERBOSE) 
	printf("const / injection completed, wrote all %d bytes\n", c); 
  }
  return 1;
}
  






