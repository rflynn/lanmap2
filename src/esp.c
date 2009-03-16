/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * ESP
 */

#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "udp.h"
#include "esp.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp_ports(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp_ports }
};

/**
 * exported interface
 */
const prot_iface Iface_ESP = {
  DINIT(id,           PROT_ESP),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "ESP"),
  DINIT(propername,   "Encapsulating Security Payload"),
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

static int test_udp_ports(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = st->frame[st->frames-1].off;
  return 4500 == u->dstport
      && 4500 == u->srcport;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  esp *e = (esp *)buf;
  /* sanity check packet */
  if (sizeof *e > len)
    return 0;
  /* convert endianness */
  e->spi = ntohl(e->spi);
  e->seq = ntohl(e->seq);
  return len;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const esp *e = f->off;
  const void *payload = (u8 *)e + sizeof *e;
  int bytes = fprintf(out,
    "%s spi=0x%08lx seq=%lu\n",
    Iface_ESP.shortname, (unsigned long)e->spi, (unsigned long)e->seq);
  bytes += dump_bytes(payload, f->len - sizeof *e, out);
  fputc('\n', stdout);
  bytes++;
  return (size_t)bytes;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

