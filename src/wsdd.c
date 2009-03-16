/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * WSDD
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "ipv4.h"
#include "ipv6.h"
#include "udp.h"
#include "wsdd.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp_port(const char *, size_t, const parse_status *);
static int test_ipv4_addr(const char *, size_t, const parse_status *);
static int test_ipv6_addr(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP,   test_udp_port  },
  { PROT_IPv4,  test_ipv4_addr },
  { PROT_IPv6,  test_ipv6_addr }
};

/**
 * exported interface
 */
const prot_iface Iface_WSDD = {
  DINIT(id,           PROT_WSDD),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "WSDD"),
  DINIT(propername,   "Web Service Dynamic Discovery"),
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

/*
2.4 Protocol Assignments
If IP multicast is used to send multicast messages described herein, they MUST be sent using the following assignments:
- DISCOVERY_PORT: port 3702 [IANA]
- IPv4 multicast address: 239.255.255.250
- IPv6 multicast address: FF02::C (link-local scope)
*/

static int test_udp_port(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = st->frame[st->frames-1].off;
  return WSDD_UDP_PORT == u->dstport; /* source port will be random */
}

static int test_ipv4_addr(const char *buf, size_t len, const parse_status *st)
{
  static const u8 Multicast[4] = { 239, 255, 255, 250 };
  const ipv4 *i = st->frame[st->frames-1].off;
  return 0 == memcmp(i->dst, Multicast, sizeof Multicast);
}

static int test_ipv6_addr(const char *buf, size_t len, const parse_status *st)
{
  static const u8 Multicast[16] = { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC };
  const ipv6 *i = st->frame[st->frames-1].off;
  return 0 == memcmp(i->dst, Multicast, sizeof Multicast);
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  /* validate and/or parse the xml some day, hopefully using a tiny,
   * self-contained xml parser */
  return len;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  int bytes = dump_chars(f->off, f->len, stdout);
  return (size_t)bytes;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

