/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Internet Protocol version 4
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "report.h"
#include "prot.h"
#include "ieee802_3.h"
#include "ipv4.h"

size_t ipv4_parse(char *, size_t, parse_frame *, const parse_status *);
size_t ipv4_dump(const parse_frame *, int options, FILE *);
static const void * addr_from(const parse_frame *);
static const void * addr_to  (const parse_frame *);

static int test_ieee802_3(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IEEE802_3, test_ieee802_3 }
  /* TODO: parse IP out of ICMP ('Redirect' and 'Destination not available')
   * messages; we can get TCP headers that way, and possibly fingerprint
   * any SYN packets we see.
   * why is this interesting?
   * because occasionally switches will not know where an address is, and
   * we'll get to peek at traffic from machines that are not normally visible
   * to us! */
};

/**
 * exported interface
 */
const prot_iface Iface_IPv4 = {
  DINIT(id,           PROT_IPv4),
  DINIT(osi,          OSI_Net),
  DINIT(shortname,    "IPv4"),
  DINIT(propername,   "Internet Protocol v4"),
  DINIT(init,         NULL),
  DINIT(unload,       NULL),
  DINIT(parse,        ipv4_parse),
  DINIT(dump,         ipv4_dump),
  DINIT(addr_type,    "4"),
  DINIT(addr_from,    addr_from),
  DINIT(addr_to,      addr_to),
  DINIT(addr_format,  ipv4_addr_format),
  DINIT(addr_local,   ipv4_addr_local),
  DINIT(parents,      sizeof Test / sizeof Test[0]),
  DINIT(parent,       Test)
};

static int test_ieee802_3(const char *buf, size_t len, const parse_status *st)
{
  const ethernet2_frame *f = (ethernet2_frame *)st->frame[st->frames-1].off;
#if 0
  printf("%s 0x0800=0x%04hx f->lentype=0x%04hx\n",
    __func__, 0x0800, f->lentype);
#endif
  return 0x0800 == f->lentype;
}

static void do_rep(const ipv4 *, const parse_status *);

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
size_t ipv4_parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  ipv4 *ip = (ipv4 *)buf;
  /* sanity check packet */
#if 0
  if (IP_IHL_MIN > len          /* 'buf' shorter than minimum header */
   || 4 != ip->version          /* wrong version */
   || ip->ihl > len              /* 'buf' too short for header */
   || IP_IHL_MIN > ip->ihl      /* ihl less than minimum */
   || IP_TOTLEN_MIN > ntohs(ip->totlen)  /* totlen less than minimum */
   || ntohs(ip->totlen) >= len) /* buffer does not contain all data */
    return 0;
#endif
  /* convert endianness */
  ip->totlen = ntohs(ip->totlen);
  ip->id = ntohs(ip->id);
  ip->checksum = ntohs(ip->checksum);
  *(u16 *)&ip->flag = ntohs(*(u16 *)&ip->flag);
  /* TODO: detect nmap 'IP protocol scan' by detecting bare IP packets
   * with no payload (and/or garbage protocol value) */
  do_rep(ip, st);
  return (size_t)ip->ihl * 4; /* ...length of the internet header
                               * in 32 bit words (Ref #1 p.10) */
}

static const void * addr_from(const parse_frame *f)
{
  const ipv4 *ip = f->off;
  return ip->src;
}

static const void * addr_to(const parse_frame *f)
{
  const ipv4 *ip = f->off;
  return ip->dst;
}

/**
 *
 */
size_t ipv4_dump(const parse_frame *f, int options, FILE *out)
{
  const ipv4 *ip = (ipv4 *)f->off;
  int bytes = fprintf(out,
    "%s v=%u ihl=%u "
    "tos(prec=%u lodel=%u hithr=%u hirel=%u ect=%u ece=%u) "
    "tlen=%u id=0x%04hx "
    "flag=0x%04hx(evil=%u dontfrag=%u morefrag=%u fragoff=%u) "
    "ttl=%u prot=0x%02x chksum=0x%04hx "
    "%u.%u.%u.%u -> "
    "%u.%u.%u.%u\n",
    Iface_IPv4.shortname, ip->version, ip->ihl,
    ip->tos.prec, ip->tos.lodelay, ip->tos.hithr, ip->tos.hirel, ip->tos.ect, ip->tos.ece,
    ip->totlen, ip->id,
    *(u16 *)&ip->flag, ip->flag.evil, ip->flag.dontfrag, ip->flag.morefrag, ip->flag.fragoff,
    ip->ttl, ip->protocol, ip->checksum,
    ip->src[0], ip->src[1], ip->src[2], ip->src[3],
    ip->dst[0], ip->dst[1], ip->dst[2], ip->dst[3]);
  return (size_t)bytes;
}

/**
 * 
 */
size_t ipv4_addr_format(char *buf, size_t len, const void *addr)
{
  const u8 *ipaddr = (u8 *)addr;
  return snprintf(buf, len, "%u.%u.%u.%u",
    ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
}

/**
 * 
 */
int ipv4_addr_cmp(const void *va, const void *vb)
{
  const u8 *a = va,
           *b = vb;
  int cmp = memcmp(a, b, 4);
  return cmp;
}

/**
 * compare two ipv4_addrs for equality based on a mask
 */
int ipv4_addr_mask_cmp(const u8 *a, const u8 *b, int mask)
{
  int cmp = 0;
  assert(mask > 0);
  assert(mask <= 32);
  while (mask > 0 && 0 == cmp) {
    u8 m = 0xFF,
       a_ = *a++,
       b_ = *b++;
    if (mask < 8)
      m <<= (8 - mask);
    a_ &= m;
    b_ &= m;
    cmp = (int)a_ - (int)b_;
  }
  return cmp;
}

int ipv4_addr_local(const void *vip)
{
  const u8 *i = vip; /* let's kick it */
#if 0 /* if we wanted to be somewhat proper about it... */
  static const ipv4_addr_mask Local[] = {
    { {  10,   0,   0,   0 },  8 },
    { { 172,  16,   0,   0 }, 12 },
    { { 192, 168,   0,   0 }, 16 }
  };
#endif
  return 10 == i[0] /* 10/8 */
    || (192 == i[0] && 168 == i[1]) /* 192.168/16 */
    || (172 == i[0] &&  16 == (i[1] & 0xF0)); /* 172.16/12 */
}

int ipv4_addr_special(const void *vip)
{
  static const u8 LocalHost[4] = { 127, 0, 0, 1 };
  const u8 *i = vip;
  return 0xFFFFFFFFUL == *(u32 *)i
      || 0x00000000UL == *(u32 *)i
      || (LocalHost[0] == i[0] && 0 == memcmp(i, LocalHost, sizeof LocalHost));
}

static void do_rep(const ipv4 *ip, const parse_status *st)
{
  /* has forwarded an IPv4 message that originated from outside, must have access
   * to another IPv4 network, therefore you are a router */
  /* FIXME: this reporting hits the database too hard for constant TCP/IP streams;
   * figure out some way to cache the results, or report randomly or something */
#if 0 /* TOO_SLOW */
  if (!ipv4_addr_local(ip->src) && !ipv4_addr_special(ip->src) && PROT_IEEE802_3 == st->frame[st->frames-1].id) {
    char macbuf[24],
         ipbuf[16];
    const ethernet2_frame *e = st->frame[st->frames-1].off;
    size_t iplen = ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
    (void)ieee802_3_addr_format(macbuf, sizeof macbuf, &e->src);
    rep_hint("M", macbuf, "IPv4.Router", "", 0);
  }
#endif
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

