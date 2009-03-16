/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * McAfee Rumor
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "ipv4.h"
#include "udp.h"
#include "mcafee-rumor.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_McAfeeRumor = {
  DINIT(id,           PROT_UDP),
  DINIT(osi,          OSI_Trans),
  DINIT(shortname,    "Rumor"),
  DINIT(propername,   "McAfee Rumor"),
  DINIT(init,         NULL),
  DINIT(unload,       NULL),
  DINIT(parse,        parse),
  DINIT(dump,         dump),
  DINIT(addr_type,    NULL),
  DINIT(addr_from,    NULL),
  DINIT(addr_to,      NULL),
  DINIT(addr_format,  NULL),
  DINIT(addr_local,   NULL),
  DINIT(parents,      sizeof Test / sizeof Test[0]),
  DINIT(parent,       Test)
};

static int test_udp(const char *buf, size_t len, const parse_status *st)
{
  const ipv4 *i = st->frame[st->frames-2].off;
  const udp *u = st->frame[st->frames-1].off;
  const rumor *r = (rumor *)buf;
  return 
      PROT_IPv4 == st->frame[st->frames-2].id
      && 0xFFFFFFFFUL == *(u32 *)i->dst           /* broadcast IP */
      && MCAFEE_RUMOR_SRC_UDP_PORT == u->srcport
      && MCAFEE_RUMOR_DST_UDP_PORT == u->dstport
      && len > 7
      && '<' == r->tag
      && ' ' == r->space
      &&   0 == memcmp("<rumor ", buf, 7);
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  rumor *r = (rumor *)buf;
  /* sanity check packet */
  if (sizeof *r > len)
    return 0;
  return len;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const rumor *r = f->off;
  int bytes = fprintf(out, "%s\n", Iface_McAfeeRumor.shortname);
  return (size_t)bytes;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

