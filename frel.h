/*
  frel.h

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

  $Id: stel.h,v 1.10 2001/01/13 22:37:37 asdfg Exp $
*/

#ifndef FREL_H
#define FREL_H

/* Input ethernet mac address string has format xx:xx:xx:xx:xx:xx */
#define ETHER_INPUT_LEN 17

#define TRUE 1
#define FALSE 0

/* Mode of operation */

extern int mode;
#define MODE_RTEORIG 1
#define MODE_RTESAME 2
#define MODE_TAKEOVER 3


/* Output control */

extern int verbose;
#define NOTVERBOSE 0
#define VERBOSE 1
#define VERYVERBOSE 2


/* IO interface parameters */

extern struct libnet_link_int *llif;	/* Libnet interface structure */
extern int ll_len;			/* Offset to IP payload */
extern char *dev;			/* Ascii name of device */
extern u_char *snd_llmac;		/* Our Ethernet MAC addr */
extern u_char *rtr_llmac;		/* Lan rtr Ethernet MAC addr */
extern u_char *tovr_llmac;		/* Takeover machine's Ethernet MAC addr */
extern u_char *snf_llmac;		/* Dummy MAC addr for sniffing */
extern struct libnet_plist_chain plist;    /* Libnet port list chain */ 
extern struct libnet_plist_chain *plist_p; /* Libnet port list chain pointer */ 


#endif /* FREL_H */




