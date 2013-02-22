/* $Id: wrappers.c,v 1.4 2001/01/20 02:33:33 asdfg Exp $ */

/* 
 Author: lorg0r
   
 Wrapper functions to avoid conflicts with Libnet ethernet defn

 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h>
#endif

char *
frel_ether_ntoa(struct ether_addr *e) {
  
  return( ether_ntoa( e ) );
}

struct ether_addr *
frel_ether_aton(char *s) {

  return ( ether_aton( s ) );
}

