/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * Internet Protocol version 6
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "ieee802_3.h"
#include "ipv6.h"

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump (const parse_frame *, int options, FILE *);
static const void * addr_from(const parse_frame *);
static const void * addr_to  (const parse_frame *);

static int test_ieee802_3(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IEEE802_3, test_ieee802_3 }
};

/**
 * exported interface
 */
const prot_iface Iface_IPv6 = {
  DINIT(id,           PROT_IPv6),
  DINIT(osi,          OSI_Net),
  DINIT(shortname,    "IPv6"),
  DINIT(propername,   "Internet Protocol v6"),
  DINIT(init,         init),
  DINIT(unload,       NULL),
  DINIT(parse,        parse),
  DINIT(dump,         dump),
  DINIT(addr_type,    "6"),
  DINIT(addr_from,    addr_from),
  DINIT(addr_to,      addr_to),
  DINIT(addr_format,  ipv6_addr_format),
  DINIT(addr_local,   ipv6_addr_local),
  DINIT(parents,      sizeof Test / sizeof Test[0]),
  DINIT(parent,       Test)
};

static int test_ieee802_3(const char *buf, size_t len, const parse_status *st)
{
  const ethernet2_frame *f = (ethernet2_frame *)st->frame[st->frames-1].off;
  printf("%s 0x86dd=0x%04hx f->lentype=0x%04hx\n",
    __func__, 0x86dd, f->lentype);
  return 0x86dd == f->lentype;
}

static void do_rep(const ipv6 *, const parse_status *);

/**
 * Validate that we have minimum requirements for an IPv4 header:
 *  - enough bytes in the buffer
 *  - version is 4
 *  - sane header and total length
 * We *could* check the checksum, the evil bit for zero, etc. but
 * I think we want to be very accepting, even if we're listening in
 * on a non-standard-comforming implementation
 *
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  ipv6 *i = (ipv6 *)buf;
  /* sanity check packet */
  /* convert endianness */
  i->payloadlen = ntohs(i->payloadlen);
  do_rep(i, st);
  return sizeof *i;
}

static char * ipv6_addr_tostr(char *, size_t, const void *);

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const ipv6 *i = (ipv6 *)f->off;
  char srcbuf[IPv6_ADDR_BUFLEN],
       dstbuf[IPv6_ADDR_BUFLEN];
  ipv6_addr_format(srcbuf, sizeof srcbuf, i->src);
  ipv6_addr_format(dstbuf, sizeof dstbuf, i->dst);
  int bytes = fprintf(out,
    "%s v=%u trafcls=%u flowlbl=0x%03x "
    "payload=%hu nexthdr=0x%02x hoplimit=%u "
    "%s -> %s\n",
    Iface_IPv6.shortname, i->version, i->trafcls, i->flowlbl,
    i->payloadlen, i->nexthdr, i->hoplimit,
    srcbuf, dstbuf);
  return (size_t)bytes;
}

/**
 * write an ipv6 address in canonical string form
 * TODO: * ISATAP -- ::0:5efe:W.X.Y.Z -- IPv4 embedded in IPv6
 *  if (12 == i && 0 == memcmp("\x00\x00\x5e\xfe", ip + 8, 4)) {
 */
size_t ipv6_addr_format(char *dst, size_t dstlen, const void *addr)
{
  const char *src = addr;
  size_t i, zoff, zlen;
  /* find the position and length of longest string of zeroes */
  zoff = memcspn(src, sizeof(ipv6_addr), "\x00", 1);
  zlen = memspn(src+zoff, sizeof(ipv6_addr)-zoff, "\x00", 1);
  printf("(zoff=%u zlen=%u) ", (unsigned)zoff, (unsigned)zlen);
  if (0 == zoff)            /* 0 prefix */
    *dst++ = ':', dstlen--; 
  if (16 == zlen) {         /* "::", unspecified address */
    *dst++ = ':', dstlen--; 
  } else if (12 == zlen) {  /* embedded IPv4 */
    dst += snprintf(dst, dstlen, ":%u.%u.%u.%u",
      (u8)src[12], (u8)src[13], (u8)src[14], (u8)src[15]);
    goto done;
  }
  for (i = 0; dstlen > 0 && i < sizeof(ipv6_addr); i++) {
    if (i < zoff || i >= zoff+zlen) {
      int odd  = i % 2,
          used = 0;
      if (i == zoff+zlen) /* first non-zero after a string of zeroes */
        *dst++ = ':', dstlen--;
      if (odd || *src)
        used = snprintf(dst, dstlen, (odd && *(src-1) ? "%02X" : "%X"), (u8)*src);
      if (used < 0)
        break;
      dst += used, dstlen -= used;
      if (i % 2 == 1 && i != 15)
        *dst++ = ':', dstlen--;
    }
    src++;
  }
done:
  *dst = '\0';
  return strlen(dst);
}

static const void * addr_from(const parse_frame *f)
{
  const ipv6 *ip = f->off;
  return ip->src;
}

static const void * addr_to(const parse_frame *f)
{
  const ipv6 *ip = f->off;
  return ip->dst;
}

int ipv6_addr_cmp(const void *va, const void *vb)
{
  const u8 *a = va,
           *b = vb;
  int cmp = (int)a[0] - (int)b[0];
  if (0 == cmp)
    cmp = memcmp(a, b, sizeof(ipv6_addr));
  return cmp;
}

enum SpecialAddr {
  SpecialAddr_Unspecified,
  SpecialAddr_Home,
  SpecialAddr_Multicast,
  SpecialAddr_Broadcast
};

enum Scope {
  Node,
  Link,
  Site,
  Vary
};

/**
 * @ref IANA "INTERNET PROTOCOL VERSION 6 MULTICAST ADDRESSES" Jan 21 2009 [web page]
 *      <URL: http://www.iana.org/assignments/ipv6-multicast-addresses> [Accessed Jan 24 2009]
 */
static const struct ipv6_multicast {
  enum Scope scope;
  const char *descr;
  ipv6_addr_mask mask;
} Multicast[] = {
  { Node, "All Nodes Address",          { "\xFF\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 128 } },
  { Node, "All Routers Address",        { "\xFF\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 128 } },
  { Node, "mDNSv6",                     { "\xFF\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFB", 128 } },
  { Link, "All Nodes Address",          { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 128 } },
  { Link, "All Routers Address",        { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 128 } },
  { Link, "Unassigned",                 { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03", 128 } },
  { Link, "DVMRP Routers",              { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04", 128 } },
  { Link, "OSPFIGP",                    { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05", 128 } },
  { Link, "OSPFIGP Designated Routers", { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06", 128 } },
  { Link, "ST Routers",                 { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07", 128 } },
  { Link, "ST Hosts",                   { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08", 128 } },
  { Link, "RIP Routers",                { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09", 128 } },
  { Link, "EIGRP Routers",              { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A", 128 } },
  { Link, "Mobile-Agents",              { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0B", 128 } },
  { Link, "SSDP",                       { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0C", 128 } },
  { Link, "All PIM Routers",            { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0D", 128 } },
  { Link, "RSVP-ENCAPSULATION",         { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0E", 128 } },
  { Link, "UPnP",                       { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0F", 128 } },
  { Link, "All MLDv2-capable routers",  { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16", 128 } },
  { Link, "All-Snoopers",               { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6A", 128 } },
  { Link, "PTP-pdelay",                 { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6B", 128 } },
  { Link, "Saratoga",                   { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6C", 128 } },
  { Link, "LL-MANET-Routers",           { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6D", 128 } },
  { Link, "IGRS",                       { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6E", 128 } },
  { Link, "mDNSv6",                     { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFB", 128 } },

  { Link, "Link Name",                  { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01", 128 } },
  { Link, "All-dhcp-agents",            { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02", 128 } },
  { Link, "Link-local Multicast Name Resolution",
                                        { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x03", 128 } },
  { Link, "DTCP Announcement",          { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x04", 128 } },
  { Link, "Soliticed-Node Address",     { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xFF\x00\x00\x00", 104 } },
  { Link, "Node Information Queries",   { "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\xFF\x00\x00\x00", 104 } },
  
  { Site, "All Routers Address",        { "\xFF\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 128 } },
  { Site, "mDNSv6",                     { "\xFF\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 128 } },
  { Site, "All-dhcp-servers",           { "\xFF\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 128 } },
  { Site, "Deprecated",                 { "\xFF\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 128 } },
  { Site, "Service Location, Version 2",{ "\xFF\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 128 } },

  /* FIXME: can't replicated proper mask, this is good enough for now but will bite us later! :-P */
  { Vary, "...",                        { "\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  12 } }
};

static int addr_is_multicast(const ipv6_addr *addr)
{
  int cmp = 1;
  unsigned i;
  /* FIXME: properly compare based on bitmask; i swear i had a function to do this already
   * but I can't find it! */
  for (i = 0; i < sizeof Multicast / sizeof Multicast[0] && cmp != 0; i++)
    cmp = ipv6_addr_cmp(addr, Multicast[i].mask.ip);
  return 0 == cmp;
}

/**
 * IPv6 Addresses that are invalid to record as source addresses
 */
static const struct ipv6_special {
  enum SpecialAddr id;
  const char *shortname,
             *longname;
  ipv6_addr addr;
} Special[] = {
  { SpecialAddr_Unspecified,  "unspec", "Unspecified",  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" },
  { SpecialAddr_Home,         "home",   "Home",         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" },
  { SpecialAddr_Broadcast,    "bcast",  "Broadcast",    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" }
};

static int addr_is_special(const ipv6_addr *addr)
{
  int cmp = 1;
  unsigned i;
  for (i = 0; i < sizeof Special / sizeof Special[0] && cmp != 0; i++)
    cmp = ipv6_addr_cmp(addr, Special[i].addr);
  return 0 == cmp;
}

/**
 * is the IPv6 a valid local address suitable for inclusion in a traffic report?
 */
int ipv6_addr_local(const void *addr)
{
  return addr_is_special((const ipv6_addr *)addr) ||
         addr_is_multicast((const ipv6_addr *)addr);
}

static void do_rep(const ipv6 *i, const parse_status *st)
{
  if (!addr_is_special(&i->src)) {
    char macbuf[32],
        ipbuf[64];
    const ethernet2_frame *e = st->frame[st->frames-1].off;
    assert(PROT_IEEE802_3 == st->frame[st->frames-1].id);
    (void)ieee802_3_addr_format(macbuf, sizeof macbuf, &e->src);
    (void)ipv6_addr_format(ipbuf, sizeof ipbuf, i->src);
    rep_addr("M", macbuf, "6", ipbuf, "IPv6", 1);
  }
}

static int init(void)
{
  assert(40 == sizeof(ipv6));
  return 1;
}

#ifdef TEST

/*
 * test the formatting of IPv6 addresses
 */
static const struct {
  const char in[16],
             *expect;
} AddrTest[] = {
  { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "::" },
  { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", "::1" },
  { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x00\x00\x01", "::127.0.0.1" },
  { "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", "FF02::2" },
  { "\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x1b\x63\xff\xfe\xa4\x95\xbc", "FE80::21B:63FF:FEA4:95BC" },
  { "\x20\x01\x0D\xB8\x00\x00\x00\x00\x00\x08\x08\x00\x20\x0c\x41\x7a", "2001:DB8::8:800:200C:417A" },
  { "\xFF\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x01", "FF01::101" }
}, *AT = AddrTest;

static void test_addr(void)
{
  unsigned i, match=0;
  char buf[48] = "";
  unsigned long canary = 0xFFFFFFFFL;
  for (i = 0; i < sizeof AddrTest / sizeof AddrTest[0]; i++) {
    unsigned ok;
    printf("#%2u in=", i);
    dump_bytes(AT->in, sizeof AT->in, stdout);
    printf(" expect=%s actual=", AT->expect);
    fflush(stdout);
    //ipv6_addr_format(buf, sizeof buf, AT->in, 0);
    format(buf, sizeof buf, AT->in, 16);
    assert(0xFFFFFFFFL == canary);
    ok = 0 == strcmp(AT->expect, buf);
    match += ok;
    printf("%s [%s]\n", buf, ok ? "OK" : "!!");
    AT++;
  }
  printf("%u/%u\n", match, i);
  assert(match == i);
}

static void test_special(void)
{
  static const struct {
    ipv6_addr addr;
    int special;
  } expect[] = {
    { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 1 },
    { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 1 },
    { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 0 },
    { "\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 0 },
    { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 1 },
  };
  unsigned i,
           matches = 0;
  printf("test_special\n");
  for (i = 0; i < sizeof expect / sizeof expect[0]; i++) {
    int res = addr_is_special(&expect[i].addr);
    printf("#%2u expected=%u result=%d\n", i, expect[i].special, res);
    matches += res == expect[i].special;
  }
  printf("matches %u/%u\n", matches, i);
  assert(matches == i);
}

int main(void)
{
  test_addr();
  test_special();
  return 0;
}
#endif

