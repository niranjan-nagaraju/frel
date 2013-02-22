/*
  ip_frag.c

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

  $Id: ip_frag.c,v 1.4 2001/01/08 19:41:56 asdfg Exp $
*/

#include "config.h"
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <libnet.h>
#include "list.h"
#include "ip_frag.h"

#if defined(OpenBSD) && (OpenBSD < 199905)
/* XXX - OpenBSD 2.4 sendto() bug - see fragrouter/test/mies.c. */
#define MINLASTFRAG	4
#else
#define MINLASTFRAG	0
#endif

int ip_frag_preserve_headers = 0;

void
ip_frag_init(int preserve_headers)
{
  ip_frag_preserve_headers = preserve_headers;
}

ELEM *
ip_frag_make(u_char *pkt, int pktlen, int fragsize)
{
  ELEM *new, *list = NULL;
  struct ip *iph = (struct ip *)pkt;
  int ip_hl = iph->ip_hl * 4;
  u_short ip_len = ntohs(iph->ip_len);
  u_char *ip_blob = pkt + ip_hl;
  u_char *ip_end = pkt + ip_len;
  u_char *p, *data;
  int len = fragsize;
  
  /* Preserve transport protocol header, if specified. */
  if (ip_frag_preserve_headers) {
    switch (iph->ip_p) {
    case IPPROTO_TCP:
      len = ((struct tcphdr *)(pkt + ip_hl))->th_off * 4;
      break;
    case IPPROTO_UDP:
      len = UDP_H;
      break;
    case IPPROTO_ICMP:
      len = ICMP_ECHO_H; /* XXX */
      break;
    case IPPROTO_IGMP:
      len = IGMP_H;
      break;
    default:
      len = fragsize; /* XXX */
      break;
    }
    if (len & 7) len = (len & ~7) + 8;
  }
  /* Make sure fragmentation is valid for this packet. */
  if (pktlen <= ip_hl + len + MINLASTFRAG || fragsize % 8 != 0)
    return NULL;

  /* Fragment packet. */
  for (p = ip_blob ; p < ip_end ; ) {

    /* Copy in IP header and data. */
    if (!(data = malloc(ip_hl + len))) return NULL;
    memcpy(data, pkt, ip_hl);
    memcpy(data + ip_hl, p, len);

    /* Correct IP length, IP fragment offset. */
    ((struct ip *)data)->ip_len = htons(ip_hl + len);
    ((struct ip *)data)->ip_off =
      htons(((p + len < ip_end) ? IP_MF : 0) | ((p - ip_blob) >> 3));

    /* Add to our IP fragment list. */
    new = list_elem(data, ip_hl + len);
    free(data);
    if (!(list = list_add(list, new)))
      return NULL;

    /* Determine next fragment size. */
    p += len;
    len = ip_end - p;
    if (len > fragsize + MINLASTFRAG)
      len = fragsize;
  }
  return (list->head);
}

ELEM *
ip_frag_add_overwrite(ELEM *list)
{
  ELEM *f, *new;
  u_char nulls[LIBNET_PACKET], *newdata;
  int newoff, newlen;

  memset(nulls, 0, sizeof(nulls));
  
  for (f = list ; f && f->next ; f = f->next) {
    struct ip *iph = (struct ip *)f->data;
    int ip_hl = iph->ip_hl * 4;

    /* Build new null data fragment, half the length of the current fragment
       and overlapping its latter half. */
    newlen = (ntohs(iph->ip_len) - ip_hl) / 2;
    newoff = ntohs(iph->ip_off) + (newlen >> 3);

    /* Copy in IP header and data. */
    if (!(newdata = malloc(ip_hl + newlen))) return NULL;
    memcpy(newdata, f->data, ip_hl);
    memcpy(newdata + ip_hl, nulls, newlen);

    /* Correct IP length, IP fragment offset. */
    ((struct ip *)newdata)->ip_len = htons(ip_hl + newlen);
    ((struct ip *)newdata)->ip_off = htons(newoff);

    /* Add null fragment after current fragment. */
    new = list_elem(newdata, LIBNET_IP_H + newlen);
    free(newdata);
    
    if (!list_add(f, new))
      return NULL;
    
    /* Swap them. */
    if (!list_swap(f))
      return NULL;
  }
  return list;
}
