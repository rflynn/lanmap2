/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * IRC
 */

#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "ipv4.h"
#include "tcp.h"
#include "irc.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_tcp_ports(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_TCP, test_tcp_ports }
};

/**
 * exported interface
 */
const prot_iface Iface_IRC = {
  DINIT(id,           PROT_IRC),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "IRC"),
  DINIT(propername,   "Internet Relay Chat"),
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

static int test_tcp_ports(const char *buf, size_t len, const parse_status *st)
{
  const tcp *t = st->frame[st->frames-1].off;
  return 6667 == t->srcport
      || 6667 == t->dstport 
      || 6666 == t->srcport 
      || 6666 == t->dstport;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  return len; /* consume all */
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  int bytes = fprintf(out, "%s ", Iface_IRC.shortname);
  bytes += dump_chars(f->off, f->len, stdout);
  fputc('\n', out);
  bytes++;
  return (size_t)bytes;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

