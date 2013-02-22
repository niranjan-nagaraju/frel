/*
  print.c

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

  $Id: print.c,v 1.9 2001/01/13 22:34:57 asdfg Exp $
*/

#ifdef STDC_HEADERS
#include <stdio.h>
#endif
#include <libnet.h>
#include "print.h"
#include "frel.h"

/* The following code is an adaptation of the print-* code in tcpdump. */

/* Compatibility */
#ifndef TCPOPT_WSCALE
#define TCPOPT_WSCALE           3       /* window scale factor (rfc1072) */
#endif
#ifndef TCPOPT_SACKOK
#define TCPOPT_SACKOK           4       /* selective ack ok (rfc2018) */
#endif
#ifndef TCPOPT_SACK
#define TCPOPT_SACK             5       /* selective ack (rfc2018) */
#endif
#ifndef TCPOLEN_SACK
#define TCPOLEN_SACK            8       /* length of a SACK block */
#endif
#ifndef TCPOPT_ECHO
#define TCPOPT_ECHO             6       /* echo (rfc1072) */
#endif
#ifndef TCPOPT_ECHOREPLY
#define TCPOPT_ECHOREPLY        7       /* echo (rfc1072) */
#endif
#ifndef TCPOPT_TIMESTAMP
#define TCPOPT_TIMESTAMP        8       /* timestamps (rfc1323) */
#endif
#ifndef TCPOPT_CC
#define TCPOPT_CC               11      /* T/TCP CC options (rfc1644) */
#endif
#ifndef TCPOPT_CCNEW
#define TCPOPT_CCNEW            12      /* T/TCP CC options (rfc1644) */
#endif
#ifndef TCPOPT_CCECHO
#define TCPOPT_CCECHO           13      /* T/TCP CC options (rfc1644) */
#endif

#ifndef IP_OFFMASK
#define IP_OFFMASK	0x1fff
#endif

#define EXTRACT_16BITS(p) \
        ((u_short)ntohs(*(u_short *)(p)))
#define EXTRACT_32BITS(p) \
        ((u_long)ntohl(*(u_long *)(p)))


void
print_ip(unsigned char *bp, int length)
{
  struct ip *iph;
  u_int ip_off, ip_hl, ip_len;

  iph = (struct ip *)bp;

  if (length < LIBNET_IP_H) {
    printf("truncated-ip %d", length);
    return;
  }
  ip_hl = iph->ip_hl * 4;
  ip_len = ntohs(iph->ip_len);

  if (length < ip_len) {
    printf("truncated-ip - %d bytes missing!", ip_len - length);
    return;
  }
  ip_off = ntohs(iph->ip_off);

  /* Handle first fragment. */
  if ((ip_off & IP_OFFMASK) == 0) {
    switch (iph->ip_p) {

    case IPPROTO_TCP:
      print_tcp(bp, ip_len);
      break;

    case IPPROTO_UDP:
      print_udp(bp, ip_len);
      break;

    case IPPROTO_ICMP:
      print_icmp(bp, ip_len);
      break;

    default:
      printf("%s > %s:", libnet_host_lookup(iph->ip_src.s_addr, 0),
	     libnet_host_lookup(iph->ip_dst.s_addr, 0));
      printf(" ip-proto-%d %d", iph->ip_p, ip_len);
      break;
    }
  }
  /* Handle more frags. */
  if (ip_off & (IP_MF|IP_OFFMASK)) {
    if (ip_off & IP_OFFMASK)
      printf("%s > %s:", libnet_host_lookup(iph->ip_src.s_addr, 0),
	     libnet_host_lookup(iph->ip_dst.s_addr, 0));
    
    printf(" (frag %d:%d@%d%s)", ntohs(iph->ip_id), ip_len - ip_hl,
	   (ip_off & IP_OFFMASK) << 3, (ip_off & IP_MF) ? "+" : "");
  }
  /* Handle don't frags. */
  else if (ip_off & IP_DF) printf(" (DF)");
    
  if (iph->ip_tos) printf(" [tos 0x%x]", (int)iph->ip_tos);
  if (iph->ip_ttl <= 1) printf(" [ttl %d]", (int)iph->ip_ttl);
}

void
print_udp(unsigned char *bp, int length)
{
  struct ip *iph;
  struct udphdr *udph;

  iph = (struct ip *)bp;
  udph = (struct udphdr *)(bp + (iph->ip_hl * 4));

  printf("%s.%d > %s.%d:", libnet_host_lookup(iph->ip_src.s_addr, 0),
	 ntohs(udph->uh_sport), libnet_host_lookup(iph->ip_dst.s_addr, 0),
	 ntohs(udph->uh_dport));

  printf(" udp %d", ntohs(udph->uh_ulen) - UDP_H);
}

void
print_icmp(unsigned char *bp, int length)
{
  struct ip *iph;
  struct libnet_icmp_hdr *icmph;

  iph = (struct ip *)bp;
  icmph = (struct libnet_icmp_hdr *)(bp + (iph->ip_hl * 4));

  printf("%s > %s:", libnet_host_lookup(iph->ip_src.s_addr, 0),
	 libnet_host_lookup(iph->ip_dst.s_addr, 0));

  printf(" icmp: type %d code %d", icmph->icmp_type, icmph->icmp_code);
}
  
void
print_tcp(unsigned char *bp, int length)
{
  struct ip *iph;
  struct tcphdr *tcph;
  u_short sport, dport, win, urp;
  u_long seq, ack;
  int len, tcp_hl;
  register char ch;

  iph = (struct ip *)bp;
  tcph = (struct tcphdr *)(bp + (iph->ip_hl * 4));
  len = length - (iph->ip_hl * 4);

  if (len < LIBNET_TCP_H) {
    printf("truncated-tcp %d", len);
    return;
  }
  sport = ntohs(tcph->th_sport);
  dport = ntohs(tcph->th_dport);
  seq = ntohl(tcph->th_seq);
  ack = ntohl(tcph->th_ack);
  win = ntohs(tcph->th_win);
  urp = ntohs(tcph->th_urp);
  tcp_hl = tcph->th_off * 4;

  printf("%s.%d > %s.%d: ", libnet_host_lookup(iph->ip_src.s_addr, 0), sport,
	 libnet_host_lookup(iph->ip_dst.s_addr, 0), dport);

  if (tcph->th_flags & (TH_SYN|TH_FIN|TH_RST|TH_PUSH)) {
    if (tcph->th_flags & TH_SYN) putchar('S');
    if (tcph->th_flags & TH_FIN) putchar('F');
    if (tcph->th_flags & TH_RST) putchar('R');
    if (tcph->th_flags & TH_PUSH) putchar('P');
  }
  else putchar('.');
  
  if (tcp_hl > len) {
    printf(" [bad hdr length]");
    return;
  }
  len -= tcp_hl;

  if (len > 0 || tcph->th_flags & (TH_SYN | TH_FIN | TH_RST))
    printf(" %lu:%lu(%d)", seq, seq + len, len);

  if (tcph->th_flags & TH_ACK) printf(" ack %lu", ack);
  printf(" win %d", win);
  if (tcph->th_flags & TH_URG) printf(" urg %d", urp);

  /* Handle options. */
  if ((tcp_hl -= LIBNET_TCP_H) > 0) {
    register const u_char *cp;
    register int i, opt, len, datalen;
    
    cp = (const u_char *)tcph + LIBNET_TCP_H;
    putchar(' ');
    ch = '<';

#define ZEROLENOPT(o) ((o) == TCPOPT_EOL || (o) == TCPOPT_NOP)
    
    while (tcp_hl > 0) {
      putchar(ch);
      opt = *cp++;
      if (ZEROLENOPT(opt))
	len = 1;
      else {
	len = *cp++;    /* total including type, len */
	if (len < 2 || len > tcp_hl)
	  goto bad;
	--tcp_hl;         /* account for length byte */
      }
      --tcp_hl;           /* account for type byte */
      datalen = 0;
      
/* Bail if "l" bytes of data are not left or were not captured  */
#define LENCHECK(l) { if ((l) > tcp_hl) goto bad; }
      
      switch (opt) {

      case TCPOPT_MAXSEG:
	printf("mss");
	datalen = 2;
	LENCHECK(datalen);
	printf(" %u", EXTRACT_16BITS(cp));
	break;
	
      case TCPOPT_EOL:
	printf("eol");
	break;
	
      case TCPOPT_NOP:
	printf("nop");
	break;
	
      case TCPOPT_WSCALE:
	printf("wscale");
	datalen = 1;
	LENCHECK(datalen);
	printf(" %u", *cp);
	break;
	
      case TCPOPT_SACKOK:
	printf("sackOK");
	if (len != 2)
	  printf("[len %d]", len);
	break;
	
      case TCPOPT_SACK:
	datalen = len - 2;
	if ((datalen % TCPOLEN_SACK) != 0 || !(tcph->th_flags & TH_ACK)) {
	  printf("malformed sack ");
	  printf("[len %d] ", datalen);
	  break;
	}
	printf("sack %d ", datalen/TCPOLEN_SACK);
	break;
	
      case TCPOPT_ECHO:
	printf("echo");
	datalen = 4;
	LENCHECK(datalen);
	printf(" %lu", EXTRACT_32BITS(cp));
	break;
	
      case TCPOPT_ECHOREPLY:
	printf("echoreply");
	datalen = 4;
	LENCHECK(datalen);
	printf(" %lu", EXTRACT_32BITS(cp));
	break;
	
      case TCPOPT_TIMESTAMP:
	printf("timestamp");
	datalen = 8;
	LENCHECK(4);
	printf(" %lu", EXTRACT_32BITS(cp));
	LENCHECK(datalen);
	printf(" %lu", EXTRACT_32BITS(cp + 4));
	break;
	
      case TCPOPT_CC:
	printf("cc");
	datalen = 4;
	LENCHECK(datalen);
	printf(" %lu", EXTRACT_32BITS(cp));
	break;
	
      case TCPOPT_CCNEW:
	printf("ccnew");
	datalen = 4;
	LENCHECK(datalen);
	printf(" %lu", EXTRACT_32BITS(cp));
	break;
	
      case TCPOPT_CCECHO:
	printf("ccecho");
	datalen = 4;
	LENCHECK(datalen);
	printf(" %lu", EXTRACT_32BITS(cp));
	break;
	
      default:
	printf("opt-%d:", opt);
	datalen = len - 2;
	for (i = 0; i < datalen; ++i) {
	  LENCHECK(i);
	  printf("%02x", cp[i]);
	}
	break;
      }
      /* Account for data printed */
      cp += datalen;
      tcp_hl -= datalen;
      
      /* Check specification against observed length */
      ++datalen;                /* option octet */
      if (!ZEROLENOPT(opt))
	++datalen;              /* size octet */
      if (datalen != len)
	printf("[len %d]", len);
      ch = ',';
      if (opt == TCPOPT_EOL)
	break;
    }
    putchar('>');
  }
  return;
  
 bad:
  fputs("[bad opt]", stdout);
  if (ch != '\0')
    putchar('>');
  return;
}

      
