/*
  tcp_seg.h

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

  $Id: tcp_seg.h,v 1.2 2001/01/08 19:41:56 asdfg Exp $
*/

#ifndef TCP_SEG_H
#define TCP_SEG_H

#include "list.h"

ELEM *tcp_seg_make(u_char *pkt, int pktlen, int segsize);

ELEM *tcp_seg_null_payload(ELEM *seg);

ELEM *tcp_seg_whack_checksums(ELEM *seg);

ELEM *tcp_seg_whack_acks(ELEM *seg);

ELEM *tcp_seg_interleave_nulls(ELEM *seg);

ELEM *tcp_seg_interleave_syns(ELEM *frag);

ELEM *tcp_seg_interleave_overwrites(ELEM *seg);

ELEM *tcp_seg_prepend_fakeclose(u_char *pkt, int pktlen);

ELEM *tcp_seg_prepend_connection(u_char *pkt, int pktlen);

ELEM *tcp_seg_prepend_junk(u_char *pkt, int pktlen);

#endif /* TCP_SEG_H */

