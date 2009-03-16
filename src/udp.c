/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * UDP
 */

#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "ipv4.h"
#include "ipv6.h"
#include "udp.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_ipv4(const char *, size_t, const parse_status *);
static int test_ipv6(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IPv4, test_ipv4 },
  { PROT_IPv6, test_ipv6 }
};

/**
 * exported interface
 */
const prot_iface Iface_UDP = {
  DINIT(id,           PROT_UDP),
  DINIT(osi,          OSI_Trans),
  DINIT(shortname,    "UDP"),
  DINIT(propername,   "User Datagram Protocol"),
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

static int test_ipv4(const char *buf, size_t len, const parse_status *st)
{
  const ipv4 *ip = st->frame[st->frames-1].off;
  printf("%s 0x11=0x%02x protocol=0x%02x\n",
    __func__, 0x11, ip->protocol);
  return 0x11 == ip->protocol;
}

static int test_ipv6(const char *buf, size_t len, const parse_status *st)
{
  const ipv6 *ip = st->frame[st->frames-1].off;
  printf("%s 0x11=0x%02x nexthdr=0x%02x\n",
    __func__, 0x11, ip->nexthdr);
  return 0x11 == ip->nexthdr;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  udp *u = (udp *)buf;
  /* sanity check packet */
  if (sizeof *u > len)
    return 0;
  /* convert endianness */
  u->srcport = ntohs(u->srcport);
  u->dstport = ntohs(u->dstport);
  u->length  = ntohs(u->length);
  u->chksum  = ntohs(u->chksum);
  return sizeof *u;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const udp *u = f->off;
  int bytes = fprintf(out,
    "%s srcport=%hu dstport=%hu length=%hu chksum=0x%04hx\n",
    Iface_UDP.shortname, u->srcport, u->dstport, u->length, u->chksum);
  return (size_t)bytes;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

