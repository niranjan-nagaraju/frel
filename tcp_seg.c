/*
  tcp_seg.c

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

  $Id: tcp_seg.c,v 1.2 2001/01/08 19:41:56 asdfg Exp $
*/

#include "config.h"

#include <libnet.h>
#include "list.h"
#include "tcp_seg.h"

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

ELEM *
tcp_seg_make(u_char *pkt, int pktlen, int segsize)
{
  ELEM *new, *list = NULL;
  struct ip *iph = (struct ip *)pkt;
  int len, ip_hl = iph->ip_hl * 4;
  struct tcphdr *tcph = (struct tcphdr *)(pkt + ip_hl);
  int tcp_hl = tcph->th_off * 4;
  u_char *tcp_blob = pkt + ip_hl + tcp_hl;
  int tcp_bloblen = ntohs(iph->ip_len) - ip_hl - tcp_hl;
  u_char *tcp_end = tcp_blob + tcp_bloblen;
  u_long tcp_newseq = ntohl(tcph->th_seq);
  u_char *p, *data;

  if (iph->ip_p != IPPROTO_TCP || tcp_bloblen <= segsize ||
      (tcph->th_flags & TH_ACK) == 0)
    return NULL;

  for (p = tcp_blob ; p < tcp_end ; p += len) {
    len = MIN(tcp_end - p, segsize);

    if (!(data = malloc(ip_hl + tcp_hl + len)))
      return NULL;

    /* Copy in headers and data. */
    memcpy(data, pkt, ip_hl + tcp_hl);
    memcpy(data + ip_hl + tcp_hl, p, len);

    /* Correct IP len, TCP seqnum, and TCP checksum. */
    ((struct ip *)data)->ip_len = htons(ip_hl + tcp_hl + len);
    ((struct tcphdr *)(data + ip_hl))->th_seq = htonl(tcp_newseq);
    libnet_do_checksum(data, IPPROTO_TCP, tcp_hl + len);
    
    tcp_newseq += len;

    /* Add it to our list of TCP packets. */
    new = list_elem(data, ip_hl + tcp_hl + len);
    free(data);
    
    if (!(list = list_add(list, new)))
      return NULL;
  }
  return (list->head);
}
    
ELEM *
tcp_seg_null_payload(ELEM *seg)
{
  struct ip *iph = (struct ip *)seg->data;
  int ip_hl = iph->ip_hl * 4;
  struct tcphdr *tcph = (struct tcphdr *)(seg->data + ip_hl);
  int tcp_hl = tcph->th_off * 4;
  int newlen = ntohs(iph->ip_len) - (ip_hl + tcp_hl);
  u_char *newdata;
  
  if (!(newdata = malloc(ip_hl + TCP_H + newlen)))
    return NULL;
  
  /* Whack the payload (including TCP options to elude PAWS). */
  memcpy(newdata, seg->data, ip_hl + TCP_H);
  memset(newdata + ip_hl + TCP_H, 0, newlen);

  /* Correct IP length, TCP header length, TCP checksum, segment length. */
  ((struct ip *)newdata)->ip_len = htons(ip_hl + TCP_H + newlen);
  ((struct tcphdr *)(newdata + ip_hl))->th_off = TCP_H / 4;
  libnet_do_checksum(newdata, IPPROTO_TCP, TCP_H + newlen);
  seg->len = ip_hl + TCP_H + newlen;

  free(seg->data);
  seg->data = newdata;
  
  return (seg);
}

ELEM *
tcp_seg_whack_checksums(ELEM *seg)
{
  ELEM *s;
  struct ip *iph;
  struct tcphdr *tcph;

  for (s = seg ; s != NULL ; s = s->next) {
    iph = (struct ip *)s->data;
    tcph = (struct tcphdr *)(s->data + (iph->ip_hl * 4));
    tcph->th_sum = htons(666);
  }  
  return (seg);
}

ELEM *
tcp_seg_whack_acks(ELEM *seg)
{
  ELEM *s;
  struct ip *iph;
  struct tcphdr *tcph;

  for (s = seg ; s != NULL ; s = s->next) {
    iph = (struct ip *)s->data;
    tcph = (struct tcphdr *)(s->data + (iph->ip_hl * 4));
    tcph->th_flags &= ~TH_ACK;
  }  
  return (seg);
}

ELEM *
tcp_seg_interleave_nulls(ELEM *seg)
{
  ELEM *s;
  struct ip *iph;
  int ip_hl;

  if (!seg) return NULL;

  for (s = seg ; s != NULL ; s = s->next) {
    s = list_dup(s);

    iph = (struct ip *)s->data;
    ip_hl = iph->ip_hl * 4;
    
    /* Whack the sequence number with something bogus. */
    ((struct tcphdr *)(s->data + ip_hl))->th_seq =
      htonl(((struct tcphdr *)(s->data + ip_hl))->th_seq);

    /* Whack the payload. */
    tcp_seg_null_payload(s);
  }
  return (seg);
}

ELEM *
tcp_seg_interleave_syns(ELEM *seg)
{
  ELEM *s, *new;
  u_char *data;

  if (!seg) return NULL;

  for (s = seg ; s && s->next ; s = s->next) {
    struct ip *iph = (struct ip *)s->data;
    int ip_hl = iph->ip_hl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(s->data + ip_hl);

    if (!(data = malloc(ip_hl + TCP_H)))
      return NULL;

    /* Copy in IP header. */
    memcpy(data, s->data, ip_hl);

    /* Correct IP length, trash IP ID, TCP sequence number. */
    ((struct ip *)data)->ip_len = htons(ip_hl + TCP_H);
    ((struct ip *)data)->ip_id = htons(iph->ip_id) * 2; /* intentional! */
    libnet_build_tcp(ntohs(tcph->th_sport), ntohs(tcph->th_dport),
		     htonl(tcph->th_seq * 2), 0, TH_SYN, ntohs(tcph->th_win),
		     ntohs(tcph->th_urp), NULL, 0, data + ip_hl);
    
    libnet_do_checksum(data, IPPROTO_TCP, TCP_H);

    /* Add it to our list of TCP packets. */
    new = list_elem(data, ip_hl + TCP_H);
    free(data);
    
    if (!(s = list_add(s, new)))
      return NULL;
  }
  return (seg);
}

ELEM *
tcp_seg_prepend_fakeclose(u_char *pkt, int pktlen)
{
  ELEM *new, *list = NULL;
  struct ip *iph = (struct ip *)pkt;
  int ip_hl = iph->ip_hl * 4;
  struct tcphdr *tcph = (struct tcphdr *)(pkt + ip_hl);
  u_char *data;

  if ((tcph->th_flags & TH_SYN) == 0)
    return NULL;

  /* Add our real SYN packet to list. */
  new = list_elem(pkt, pktlen);
  if (!(list = list_add(list, new)))
    return NULL;
  
  /* Add our fake FIN packet. */
  if (!(data = malloc(ip_hl + TCP_H)))
    return NULL;

  memcpy(data, pkt, ip_hl);
  ((struct ip *)data)->ip_len = htons(ip_hl + TCP_H);
  ((struct ip *)data)->ip_id = htons(iph->ip_id) * 2; /* intentional! */
  libnet_build_tcp(ntohs(tcph->th_sport), ntohs(tcph->th_dport),
		   ntohl(tcph->th_seq) + 1, ntohl(tcph->th_ack),
		   TH_FIN, 0, ntohs(tcph->th_urp), NULL, 0, data + ip_hl);
  
  new = list_elem(data, ip_hl + TCP_H);
  free(data);
  
  if (!(list = list_add(list, new)))
    return NULL;

  /* Add our fake RST packet. */
  if (!(data = malloc(ip_hl + TCP_H)))
    return NULL;

  memcpy(data, pkt, ip_hl);
  ((struct ip *)data)->ip_len = htons(ip_hl + TCP_H);
  ((struct ip *)data)->ip_id = htons(iph->ip_id) * 2 + 1; /* intentional! */
  libnet_build_tcp(ntohs(tcph->th_sport), ntohs(tcph->th_dport),
		   ntohl(tcph->th_seq) + 2, ntohl(tcph->th_ack),
		   TH_RST, 0, ntohs(tcph->th_urp), NULL, 0, data + ip_hl);

  new = list_elem(data, ip_hl + TCP_H);
  free(data);
  
  if (!(list = list_add(list, new)))
    return NULL;
  
  return (list->head);
}

ELEM *
tcp_seg_prepend_connection(u_char *pkt, int pktlen)
{
  ELEM *new, *list = NULL;
  struct ip *iph = (struct ip *)pkt;
  int ip_hl = iph->ip_hl * 4;
  struct tcphdr *tcph = (struct tcphdr *)(pkt + ip_hl);
  u_char *data;

  if ((tcph->th_flags & TH_SYN) == 0)
    return NULL;

  /* Add our decoy SYN packet. */
  if (!(data = malloc(ip_hl + TCP_H)))
    return NULL;

  memcpy(data, pkt, ip_hl);
  ((struct ip *)data)->ip_len = htons(ip_hl + TCP_H);
  ((struct ip *)data)->ip_id = htons(iph->ip_id) * 2; /* intentional! */
  libnet_build_tcp(ntohs(tcph->th_sport), ntohs(tcph->th_dport),
		   ntohl(tcph->th_seq) * 2, 0, TH_SYN, ntohs(tcph->th_win),
		   0, NULL, 0, data + ip_hl);
  libnet_do_checksum(data, IPPROTO_TCP, TCP_H);
  new = list_elem(data, ip_hl + TCP_H);
  free(data);
  
  if (!(list = list_add(list, new)))
    return NULL;

  /* Add our decoy RST packet, in case the attacker is filtering hers. */
  if (!(data = malloc(ip_hl + TCP_H)))
    return NULL;

  memcpy(data, pkt, ip_hl);
  ((struct ip *)data)->ip_len = htons(ip_hl + TCP_H);
  ((struct ip *)data)->ip_id = htons(iph->ip_id) * 2 + 1; /* intentional! */
  libnet_build_tcp(ntohs(tcph->th_sport), ntohs(tcph->th_dport),
		   ntohl(tcph->th_seq) * 2 + 1, 0, TH_RST, ntohs(tcph->th_win),
		   0, NULL, 0, data + ip_hl);
  libnet_do_checksum(data, IPPROTO_TCP, TCP_H);
  new = list_elem(data, ip_hl + TCP_H);
  free(data);
  
  if (!(list = list_add(list, new)))
    return NULL;
  
  /* Add our real SYN packet to list. */
  new = list_elem(pkt, pktlen);
  if (!(list = list_add(list, new)))
    return NULL;
  
  return (list->head);
}
  
ELEM *
tcp_seg_prepend_junk(u_char *pkt, int pktlen)
{
  ELEM *new, *list = NULL;
  struct ip *iph = (struct ip *)pkt;
  int ip_hl = iph->ip_hl * 4;
  struct tcphdr *tcph = (struct tcphdr *)(pkt + ip_hl);
  u_char *data;
  int i;

  if ((tcph->th_flags & TH_SYN) == 0)
    return NULL;

  for (i = 0; i < 500 ; i++) {
    if (!(data = malloc(ip_hl + TCP_H + LIBNET_PACKET)))
      return NULL;

    /* Copy over IP header. */
    memcpy(data, pkt, ip_hl);

    /* Correct IP length, IP ID. */
    ((struct ip *)data)->ip_len = htons(ip_hl + TCP_H + LIBNET_PACKET);
    ((struct ip *)data)->ip_id = htons(iph->ip_id + i); /* intentional! */

    /* Add TCP header, null payload, and fix checksum. */
    libnet_build_tcp(ntohs(tcph->th_sport), ntohs(tcph->th_dport),
		     i, 666, TH_ACK, ntohs(tcph->th_win),
		     ntohs(tcph->th_urp), NULL, 0, data + ip_hl);
    memset(data + ip_hl + TCP_H, 0, LIBNET_PACKET);
    libnet_do_checksum(data, IPPROTO_TCP, TCP_H);
    
    new = list_elem(data, ip_hl + TCP_H + LIBNET_PACKET);
    free(data);
    
    if (!(list = list_add(list, new)))
      return NULL;
  }
  /* Add our real SYN packet. */
  new = list_elem(pkt, pktlen);
  if (!(list = list_add(list, new)))
    return NULL;
  
  return (list->head);
}

ELEM *
tcp_seg_interleave_overwrites(ELEM *seg)
{
  ELEM *s, *new;
  u_char nulls[LIBNET_PACKET], *newdata;
  u_long newseq;
  int newlen;

  memset(nulls, 0, sizeof(nulls));
  
  for (s = seg ; s && s->next ; s = s->next) {
    struct ip *iph = (struct ip *)s->data;
    int ip_hl = iph->ip_hl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(s->data + ip_hl);
    int tcp_hl = tcph->th_off * 4;

    /* Build new null data segment, half the length of the current segment
       and overlapping its latter half. */
    newlen = (ntohs(iph->ip_len) - (ip_hl + tcp_hl)) / 2;
    newseq = ntohl(tcph->th_seq) + newlen;

    if (!(newdata = malloc(ip_hl + TCP_H + newlen)))
      return NULL;

    /* Copy in IP, TCP headers and data. */
    memcpy(newdata, s->data, ip_hl + TCP_H);
    memcpy(newdata + ip_hl + TCP_H, nulls, newlen);

    /* Correct IP length, TCP header length, TCP seqnum, TCP checksum. */
    ((struct ip *)newdata)->ip_len = htons(ip_hl + TCP_H + newlen);
    ((struct tcphdr *)(newdata + ip_hl))->th_seq = htonl(newseq);
    ((struct tcphdr *)(newdata + ip_hl))->th_off = TCP_H / 4; /* XXX - PAWS! */
    libnet_do_checksum(newdata, IPPROTO_TCP, TCP_H + newlen);

    /* Add null fragment after current fragment. */
    new = list_elem(newdata, ip_hl + TCP_H + newlen);
    free(newdata);
    
    if (!list_add(s, new))
      return NULL;
    
    /* Swap them. */
    if (!list_swap(s))
      return NULL;
  }
  return (seg);
}
