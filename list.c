/*
  list.c

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

  $Id: list.c,v 1.4 2001/01/17 19:45:20 asdfg Exp $
*/

#include "config.h"

#ifdef STDC_HEADERS
#include <stdlib.h>
#endif

#include <string.h>
#include "list.h"

ELEM *
list_elem(unsigned char *data, int len)
{
  ELEM *new;
  
  if ((new = malloc(sizeof(ELEM))) == NULL ||
      (new->data = malloc(len)) == NULL) {
    if (new) free(new);
    return NULL;
  }
  memcpy(new->data, data, len);
  new->len = len;
  new->head = NULL;
  new->prev = NULL;
  new->next = NULL;
  
  return new;
}

ELEM *
list_add(ELEM *elem, ELEM *new)
{
  if (!elem) {
    new->head = new;
    new->prev = NULL;
    new->next = NULL;
  }
  else {
    new->head = elem->head;
    new->next = elem->next;
    new->prev = elem;
    elem->next = new;
    if (new->next) new->next->prev = new;
  }
  return (new);
}

int
list_free(ELEM *elem)
{
  ELEM *next, *f = elem;

  if (f->prev) f->prev->next = NULL;
  
  for ( ; f != NULL ; f = next) {
    next = f->next;
    free(f->data);
    free(f);
  }
  return 1;
}

ELEM *
list_last(ELEM *elem)
{
  ELEM *f;

  if (!elem) return NULL;
  for (f = elem ; f->next != NULL ; f = f->next) ;
  return (f);
}
  
ELEM *
list_dup(ELEM *elem)
{
  ELEM *dup = NULL;

  if (elem && (dup = list_elem(elem->data, elem->len)) != NULL)
    list_add(elem, dup);
  
  return (dup);
}

ELEM *
list_swap(ELEM *elem)
{
  ELEM *f, *next = elem->next;

  if (next) {
    elem->next = next->next;
    next->prev = elem->prev;
    elem->prev = next;
    next->next = elem;

    if (elem->next) elem->next->prev = elem;

    if (next->prev) next->prev->next = next;
    else {
      for (f = next ; f != NULL ; f = f->next)
	f->head = next;
    }
  }
  else if (elem->prev == elem->head) { /* last elem of two. */
    return list_swap(elem->head);
  }
  else { /* last elem of a few, swap with head. */
    next = elem->head;
    next->prev = elem->prev;
    elem->prev = NULL;
    elem->next = next->next;
    next->next = NULL;
    if (elem->next)
      elem->next->prev = elem;
    if (next->prev)
      next->prev->next = next;
    
    for (f = elem ; f != NULL ; f = f->next)
      f->head = elem;
  }
  return (elem);
}

ELEM *
list_randomize(ELEM *elem)
{
  int i;
  ELEM *f;
  
  /* XXX - lame. */
  for (i = 0, f = elem->head ; f && f->next != NULL ; f = f->next, i++)
    if (i % 2) f = list_swap(f);
  
  return (elem->head);
}
