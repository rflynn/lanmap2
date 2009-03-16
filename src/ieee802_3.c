/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Code supporting IEEE 802.3
 *
 * References:
 * #1 "IEEE Std 802.3.-2005" http://standards.ieee.org/getieee802/download/802.3-2005_section1.pdf
 *
 */

#include <assert.h>
#include <stdio.h>
#include <string.h> /* memcmp */
#include <arpa/inet.h>
#include <pcap.h>
#include "env.h"
#include "prot.h"
#include "logical.h"
#include "ieee802_3.h"

static const ieee802_3_mac_addr Addr;
static const ethernet2_frame    Frame;
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int, FILE *);
static const void * ieee802_3_addr_from(const parse_frame *);
static const void * ieee802_3_addr_to  (const parse_frame *);

static int test_logical(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_LOGICAL, test_logical }
};

const prot_iface Iface_IEEE802_3 = {
  DINIT(id,           PROT_IEEE802_3),
  DINIT(osi,          OSI_Link),
  DINIT(shortname,    "802.3"),
  DINIT(propername,   "IEEE 802.3"),
  DINIT(init,         NULL),
  DINIT(unload,       NULL),
  DINIT(parse,        parse),
  DINIT(dump,         dump),
  DINIT(addr_type,    "M"),
  DINIT(addr_from,    ieee802_3_addr_from),
  DINIT(addr_to,      ieee802_3_addr_to),
  DINIT(addr_format,  ieee802_3_addr_format),
  DINIT(addr_local,   ieee802_3_addr_local),
  DINIT(parents,      sizeof Test / sizeof Test[0]),
  DINIT(parent,       Test)
};

/**
 * test a logical frame for IEEE 802.3
 */
static int test_logical(const char *buf, size_t len, const parse_status *st)
{
  const logical_frame *f = st->frame[st->frames-1].off;
#if 0
  printf("%s DLT_EN10MB=%d f->type=%d\n",
    __func__, DLT_EN10MB, f->type);
#endif
  return
    len >= sizeof *f
    && len >= sizeof(ethernet2_frame)
    && DLT_EN10MB == f->type;
}

/**
 *
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  ethernet2_frame *e = (ethernet2_frame *)buf;
  if (len < sizeof *e)
    return 0;
  /* convert byte order */
  e->lentype = ntohs(e->lentype);
  return sizeof *e;
}

static const void * ieee802_3_addr_from(const parse_frame *f)
{
  const ethernet2_frame *e = f->off;
  return &e->src;
}

static const void * ieee802_3_addr_to(const parse_frame *f)
{
  const ethernet2_frame *e = f->off;
  return &e->dst;
}

/**
 *
 */
static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const ethernet2_frame *e = f->off;
  int used = fprintf(out,
    "%s "
    "src=%02x:%02x:%02x:%02x:%02x:%02x "
    "dst=%02x:%02x:%02x:%02x:%02x:%02x "
    "%s=",
    Iface_IEEE802_3.shortname,
    e->src.o[0], e->src.o[1], e->src.o[2],
    e->src.o[3], e->src.o[4], e->src.o[5],
    e->dst.o[0], e->dst.o[1], e->dst.o[2],
    e->dst.o[3], e->dst.o[4], e->dst.o[5],
    (IEEE802_3_IS_LEN(e->lentype) ? "len" : "type"));
  /* length is printed as decimal, type as hex */
  used += fprintf(out,
    (IEEE802_3_IS_LEN(e->lentype) ? "%hu" : "0x%04hx"),
    e->lentype);
  fputc('\n', out);
  used++;
  return (size_t)used;
}

/**
 * format IEEE mac addr to human-readable string
 */
size_t ieee802_3_addr_format(char *s, size_t len, const void *vaddr)
{
  const ieee802_3_mac_addr *addr = vaddr;
  int used = snprintf(s, len, "%02x:%02x:%02x:%02x:%02x:%02x",
                      addr->o[0], addr->o[1], addr->o[2],
                      addr->o[3], addr->o[4], addr->o[5]);
  return (size_t)used;
}

int ieee802_3_addr_local(const void *addr)
{
  return 0 != memcmp(addr, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) /* broadcast */
      /* @ref en-bcast.txt */
      && 0 != memcmp(addr, "\x09\x00",                 2) /* AppleTalk and a bunch of crap */
      && 0 != memcmp(addr, "\x33\x33",                 2) /* IPv6 neighbor discovery */
      && 0 != memcmp(addr, "\x01\x00\x5e",             3) /* DoD Multicast */
      && 0 != memcmp(addr, "\x03\x00\x00\x00",         4) /* Token Ring crap */
      && 0 != memcmp(addr, "\x01\x00\x0C\xCC\xCC\xCC", 6) /* CDP */
      && 0 != memcmp(addr, "\x01\x00\x0C\xCC\xCC\xCD", 6) /* CDP */
      && 0 != memcmp(addr, "\xCF\x00\x00\x00\x00\x00", 6) /* Loopback */
      && 0 != memcmp(addr, "\xFF\xFF\x00\x60\x00\x04", 6) /* Lantastic */
      && 0 != memcmp(addr, "\xFF\xFF\x00\x40\x00\x01", 6) /* Lantastic */
      && 0 != memcmp(addr, "\xFF\xFF\x01\xE0\x00\x04", 6) /* Lantastic */
      ;
}

/**
 * compare 2 IEEE 802.3 MAC addresses for equality
 * @return 0 if equal, positive if a>b, negative if b>a
 */
int ieee802_3_mac_addr_cmp(const void *a, const void *b)
{
  int cmp = ((ieee802_3_mac_addr *)a)->o[0] - 
            ((ieee802_3_mac_addr *)b)->o[0];
  if (0 == cmp)
    cmp = memcmp(((ieee802_3_mac_addr *)a)->o,
                 ((ieee802_3_mac_addr *)b)->o, sizeof Addr.o);
  return cmp;
}

/**
 * Verify that our data structures are sane on this platform
 */
static void sanity_check(void)
{
  assert("Each address field shall be 48 bits in length" /* Ref #1 S 3.2.3.a */
    && IEEE802_3_addressSize == sizeof(ieee802_3_mac_addr) * 8);
}

int ieee802_3_init(void)
{
  sanity_check();
  return 1;
}

#ifdef TEST

int main(void)
{
  ieee802_3_init();
  return 0;
}

#endif


