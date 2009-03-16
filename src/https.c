/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * HTTPS
 */

#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "tcp.h"
#include "https.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_tcp_port(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_TCP, test_tcp_port }
};

/**
 * exported interface
 */
const prot_iface Iface_HTTPS = {
  DINIT(id,           PROT_HTTPS),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "HTTPS"),
  DINIT(propername,   "Hypertext Transfer Protocol over Secure Socket Layer"),
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

static int test_tcp_port(const char *buf, size_t len, const parse_status *st)
{
  const tcp *t = st->frame[st->frames-1].off;
  return 443 == t->dstport
      || 443 == t->srcport;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  return len;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  int bytes = fprintf(out, "%s\n", Iface_HTTPS.shortname);
  bytes += dump_bytes(f->off, f->len, out);
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

