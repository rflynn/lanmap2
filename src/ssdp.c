/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * SSDP
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "ipv4.h"
#include "ipv6.h"
#include "udp.h"
#include "http.h"
#include "ssdp.h"

static ipv4_addr SSDP_IP;

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump (const parse_frame *, int options, FILE *);

static int test_ipv4_udp(const char *, size_t, const parse_status *);
static int test_ipv6_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_ipv4_udp },
  { PROT_UDP, test_ipv6_udp }
};

/**
 * method dictionary, tied to 'enum SSDP_Method'
 */
static const char *Meth[] = {
  "(None)",
  "NOTIFY",
};

/**
 * exported interface
 */
const prot_iface Iface_SSDP = {
  DINIT(id,           PROT_SSDP),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "SSDP"),
  DINIT(propername,   "Simple Service Discovery Protocol"),
  DINIT(init,         init),
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

/**
 *
 */
static int test_ipv4_udp(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = st->frame[st->frames-1].off;
  const ipv4 *i = st->frame[st->frames-2].off;
  return
       SSDP_UDP_PORT == u->srcport
    && SSDP_UDP_PORT == u->dstport
    && PROT_IPv4     == st->frame[st->frames-2].id
    && 0             == ipv4_addr_cmp(SSDP_IP, &i->dst);
}

/**
 *
 */
static int test_ipv6_udp(const char *buf, size_t len, const parse_status *st)
{
  static const u8 Multicast[] = { 0xFF, 0x2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC };
  const udp *u = st->frame[st->frames-1].off;
  const ipv6 *i = st->frame[st->frames-2].off;
#if 1
  char addrbuf[48],
       cmpbuf[48];
  ipv6_addr_format(addrbuf, sizeof addrbuf, i->dst);
  ipv6_addr_format(cmpbuf, sizeof cmpbuf, i->dst);
  printf("%s udp(srcport=%hu dstport=%hu) ipv6(addr=%s cmp=%s)\n",
    __func__, u->srcport, u->dstport, addrbuf, cmpbuf);
#endif
  return
       SSDP_UDP_PORT == u->srcport
    && SSDP_UDP_PORT == u->dstport
    && PROT_IPv6     == st->frame[st->frames-2].id
    && 0             == ipv6_addr_cmp(Multicast, i->dst);
}

static void report(const parse_status *, const parse_frame *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  static ssdp s;
  size_t bytes;
  memset(&s, 0, sizeof s);
  bytes = http_parse(buf, len, f, st, &s.h);
  f->pass = &s;
#ifndef TEST
  report(st, f);
#endif
  return bytes;
}

static size_t dump(const parse_frame *f, int opt, FILE *out)
{
  const ssdp *s = f->pass;
  return http_dump(f, opt, out, &s->h, Iface_SSDP.shortname);
}

static void report(const parse_status *st, const parse_frame *f)
{
  char ipbuf[48];
  const ssdp *s = f->pass;
  const http_req *r = &s->h.data.req;
  const http_headers *h = &r->headers;
  const parse_frame *fi = st->frame + st->frames - 2;
  const ipv4 *ip = fi->off;
  unsigned i;
  if (PROT_IPv4 == fi->id) {
    (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
    for (i = 0; i < h->cnt; i++) {
      const struct head_kv *kv = h->h+i;
      const char *name;
      if (0 == kv->key.len || 0 == kv->val.cnt)
        continue;
      if (6 == kv->key.len && 0 == strncasecmp(kv->key.start, "SERVER", 6))
        name = "SSDP.Server";
      else if (8 == kv->key.len && 0 == strncasecmp(kv->key.start, "LOCATION", 8))
        name = "SSDP.Location";
      else if (2 == kv->key.len && 0 == strncasecmp(kv->key.start, "NT", 2))
        name = "SSDP.NT";
      else
        name = 0;
      if (name) {
        fprintf(stderr, "%s %s %.*s\n", ipbuf, name, (unsigned)kv->val.p[0].len, kv->val.p[0].start);
        rep_hint("4", ipbuf, name, kv->val.p[0].start, kv->val.p[0].len);
      }
    }
  } else {
    unsigned i;
    printf("%s:%s:expected PROT_IPv4(%u) but got (%u)! st->frames(%u):",
      __FILE__, __func__, PROT_IPv4, fi->id, st->frames);
    for (i = 0; i < st->frames; i++)
      printf(" (#%u:%u)", i, st->frame[i].id);
    fputc('\n', stdout);
  }
}

static int init(void)
{
  memcpy(SSDP_IP, "\xEF\xFF\xFF\xFA", 4);
  return 1;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[512];
} TestCase[] = {
  { 509, "NOTIFY\x20*\x20HTTP/1.1\x0d\x0aHost:[FF02::C]:1900\x0d\x0aNT:urn:schemas-upnp-org:service:ConnectionManager:1\x0d\x0aNTS:ssdp:alive\x0d\x0aLocation:http://[fe80::a554:756d:14a0:7a7b]:2869/upnphost/udhisapi.dll?content=uuid:4810d742-42fc-4a05-8cd1-e5b7cfe84ddd\x0d\x0aUSN:uuid:4810d742-42fc-4a05-8cd1-e5b7cfe84ddd::urn:schemas-upnp-org:service:ConnectionManager:1\x0d\x0a""Cache-Control:max-age=900\x0d\x0aServer:Microsoft-Windows-NT/5.1\x20UPnP/1.0\x20UPnP-Device-Host/1.0\x0d\x0aOPT:\"http://schemas.upnp.org/upnp/1/0/\";\x20ns=01\x0d\x0a""01-NLS:9af98ef07b801b2acb4b5f023533cf9c\x0d\x0a\x0d\x0a" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_SSDP, T->len, T->txt, NULL };
    printf("#%2u: ", i);
    dump_chars(T->txt, T->len, stdout);
    fputc('\n', stdout);
    parse(T->txt, T->len, &pf, NULL);
    dump(&pf, 0, stdout);
    fputc('\n', stdout);
    T++;
  }
}

int main(void)
{
  test();
  return 0;
}
#endif


