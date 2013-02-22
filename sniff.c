/*
  sniff.c

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

  $Id: sniff.c,v 1.18 2001/01/13 22:35:53 asdfg Exp $
*/

#include "config.h"

#ifdef STDC_HEADERS
#include <stdio.h>
#endif
#ifdef HAVE_UNISTD_H
#include <sys/param.h>
#endif
#include <pcap.h>
#include <libnet.h>
#include "sniff.h"
#include "frel.h"
#include "send.h"
#include "wrappers.h"

pcap_t *sniff_pd;

u_long fragproxy_ip = 0,		/* Binary network representation of fragproxy ip addr */
  atksrc_ip = 0;			/* Binary network representation of attacker's src ip addr */

int
sniff_init(char *ebuf,			/* Buffer for error msgs */
	   const char *ethersniff	/* Ascii ethernet mac addr for sniffing */
	   )
{
  char filter[BUFSIZ];
  u_long llip;
  u_int net, mask;
  struct bpf_program fcode;

  /* Find interface name */
  if (!(dev)) {
    if (!(dev = pcap_lookupdev(ebuf)))
      return 0;
  }

  /* Get interface IP and MAC address and link layer header length. */
  if (!(llif = libnet_open_link_interface(dev, ebuf)))
    return 0;

  if (!(llip = libnet_get_ipaddr(llif, dev, ebuf)))
    return 0;

  if (!(snd_llmac = (u_char *) libnet_get_hwaddr(llif, dev, ebuf)))
    return 0;
  

  llip = ntohl(llip);
  fragproxy_ip = llip;			/* Save the fragproxy's binary network IP addr */
 
  if (!llif->linkoffset)
    ll_len = 14; /* XXX - assume Ethernet, if libnet fails us here. */
  else 
    ll_len = llif->linkoffset;


  /* Generate / compile packet filter and initialize interface(s) depending on opn mode */

  switch( mode ) {
  case MODE_RTEORIG:		/* Vanilla fragrouter configuration */

    libnet_close_link_interface(llif);	/* Original fragrtr does raw sockets */


    /* Generate packet filter. We are sniffing in promiscuous mode,
       so must be specific. */

    snprintf(filter, sizeof(filter),
	     "ip and ether dst %s and not dst %s and not ip broadcast",
	     frel_ether_ntoa((struct ether_addr *)snd_llmac),
	     libnet_host_lookup(llip, 0));
    break;

  case MODE_RTESAME:

    snprintf(filter, sizeof(filter),
	     "ip and ether dst %s and not ip broadcast",
	     ethersniff);
    break;

  case MODE_TAKEOVER:

    snprintf(filter, sizeof(filter),
	     "ip and (ether dst %s or (ether dst %s and dst %s)) and not ip broadcast",
	     ethersniff,
	     frel_ether_ntoa((struct ether_addr *)snd_llmac),
	     libnet_host_lookup(llip, 0));
    break;

  default:			/* Shouldn't come here */

    strcpy(ebuf,"Internal error 10 in sniff.c");
    return(0);
  }



  if (verbose >= VERBOSE)
    fprintf(stderr, "frel: filter  %s\n", filter);
  
  /* Open interface for sniffing, set promiscuous mode. */
  if (pcap_lookupnet(dev, &net, &mask, ebuf) == -1)
    return 0;

  if (!(sniff_pd = pcap_open_live(dev, 2048, 1, 1024, ebuf)))
    return 0;
  
  if (pcap_compile(sniff_pd, &fcode, filter, 1, mask) < 0) {
    strcpy(ebuf, pcap_geterr(sniff_pd));
    return 0;
  }
  if (pcap_setfilter(sniff_pd, &fcode) == -1) {
    strcpy(ebuf, pcap_geterr(sniff_pd));
    return 0;
  }

  if (verbose >= VERBOSE)
    fprintf(stderr, "frel: sniffing on %s\n", dev);
  
  return 1;
}

void
sniff_loop(sniff_handler attack)
{
  struct pcap_pkthdr pkthdr;
  struct ip *iph;			/* IP packet header */
  struct libnet_ethernet_hdr *eph;	/* Ethernet packet header */
  struct tcphdr *tph;			/* Tcp packet header */
  struct udphdr *uph;			/* Udp packet header */
  int ip_hl = 0;
  u_char *pkt;
  int len;

  u_int16_t tmp16 = 0;
  u_int32_t tmp32 = 0;


  for (;;) {
    if ((pkt = (char *)pcap_next(sniff_pd, &pkthdr)) != NULL) {
      iph = (struct ip *)(pkt + ll_len);	/* Point to ip header inside packet */

      len = ntohs(iph->ip_len);		/* Length of input IP packet */
      if (len > pkthdr.len)
	len = pkthdr.len;
 
      ip_hl = iph->ip_hl * 4;		/* Length of IP hdr */

      switch( mode ) {
   
      case MODE_RTEORIG:
	break;

      case MODE_RTESAME:
	break;

      case MODE_TAKEOVER:
	eph = (struct libnet_ethernet_hdr *) pkt;	/* Point to ethernet header inside packet */

	/* If packet is going to dummy ethersniff addr then ... */

	if (!memcmp( eph->ether_dhost, snf_llmac, ETHER_ADDR_LEN)) {
	  if (iph->ip_p == IPPROTO_TCP) {
	    tph = (struct tcphdr *)(pkt + ll_len + ip_hl);
	    if (!port_chk(ntohs(tph->th_dport)))	/* ignore tcp packets that are not FROM our ports */
	      continue;
	    if (tph -> th_flags & TH_RST) {	/* If is a TCP reset then fwd to takeover host */
						/*    as well to keep him out of our ports */

	      /* Exchange source/dest IP addr and ports so that looks like reset came from */
	      /*    the remote server */
	      
	      tmp32 = iph->ip_src.s_addr;
	      iph->ip_src.s_addr = iph->ip_dst.s_addr;
	      iph->ip_dst.s_addr = tmp32;

	      tmp16 = tph->th_sport;      
	      tph->th_sport = tph->th_dport;
	      tph->th_dport = tmp16;

	      send_raw_packet(pkt + ll_len, len, snd_llmac, tovr_llmac);

	      /* Now swap them back again to send a RST on to the remote server */
	      
	      tmp32 = iph->ip_src.s_addr;
	      iph->ip_src.s_addr = iph->ip_dst.s_addr;
	      iph->ip_dst.s_addr = tmp32;

	      tmp16 = tph->th_sport;      
	      tph->th_sport = tph->th_dport;
	      tph->th_dport = tmp16;

 
	    }
	  }
	  else {
	    if (iph->ip_p == IPPROTO_UDP) {
	      uph = (struct udphdr *)(pkt + ll_len + ip_hl);
	      if (!port_chk(ntohs(uph->uh_dport))) /* idem for udp packets */
		continue;
	    }
	  }
	}
	/* else if packet is coming to our interface ... */

	else {
	  if (!memcmp( eph->ether_dhost, snd_llmac, ETHER_ADDR_LEN)) {
	    if (iph->ip_p == IPPROTO_TCP) {
	    tph = (struct tcphdr *)(pkt + ll_len + ip_hl);
	    if (port_chk(ntohs(tph->th_sport)))	/* ignore tcp packets that are FOR our ports since */
	      /*    our stack has already seen the packet */
		continue;
	  }
	  else {
	    if (iph->ip_p == IPPROTO_UDP) {
	    uph = (struct udphdr *)(pkt + ll_len + ip_hl);
	    if (port_chk(ntohs(uph->uh_sport)))	/* idem for udp packets */
	      continue;
	    }
	  }
	  /* The packet doesn't interest us, but should send it on to the real machine */
	  
	    send_raw_packet(pkt + ll_len, len, (u_char *)eph->ether_shost, tovr_llmac);
	    continue;
	  }
	}
	break;

      default:				/* Shouldn't come here */
	fprintf(stderr, "frel: Internal error 20 in sniff.c.");
	exit(1);
      }
      
      attack(pkt + ll_len, len);
    }
  }
}

int
port_chk(const u_short chk_port) {		/* Port to be checked */ 
  struct libnet_plist_chain *p;

  p = plist_p;					/* Point to start of the port list chain */
  /* Loop through the linked list of ports to see if ours is there */
  for (p = plist_p; p; p = p->next) {
    if ((chk_port >= p->bport) && (chk_port <= p->eport)) /* If port is inside range then all done */
      return TRUE;
  }
  return FALSE;
}







