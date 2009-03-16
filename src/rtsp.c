/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * RTSP
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
#include "udp.h"
#include "http.h"
#include "rtsp.h"

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump (const parse_frame *, int options, FILE *);

static int test_udp_port(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp_port }
};

/**
 * exported interface
 */
const prot_iface Iface_RTSP = {
  DINIT(id,           PROT_RTSP),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "RTSP"),
  DINIT(propername,   "Real Time Streaming Protocol"),
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
static int test_udp_port(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = st->frame[st->frames-1].off;
  return rtsp_is_udp_port(u->srcport)
      || rtsp_is_udp_port(u->dstport);
}

static void report(const parse_status *, const parse_frame *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  static rtsp r; /* NOTE: static storage; not thread-safe but otherwise ok;
                  * we can't have more than one instance of RTSP data per packet,
                  * and the data doesn't need to live longer than a parse/dump cycle */
  size_t bytes;
  memset(&r, 0, sizeof r);
  bytes = http_parse(buf, len, f, st, &r.h);
  f->pass = &r;
#ifndef TEST
  report(st, f);
#endif
  return bytes;
}

static size_t dump(const parse_frame *f, int opt, FILE *out)
{
  const rtsp *r = f->pass;
  return http_dump(f, opt, out, &r->h, Iface_RTSP.shortname);
}

static void report(const parse_status *st, const parse_frame *f)
{
  char ipbuf[48];
  const rtsp *r = f->pass;
  const http_req *req = &r->h.data.req;
  const http_headers *h = &req->headers;
  const parse_frame *fi = st->frame + st->frames - 2;
  const ipv4 *ip = fi->off;
  unsigned i;
  assert(PROT_IPv4 == fi->id);
  (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
  /*
   * the "DESCRIBE" method provides an RTSP URL; let's record it for later
   */
  if (8 == req->meth.len && 0 == strncasecmp(req->meth.start, "DESCRIBE", 8)) {
    rep_hint("4", ipbuf, "RTSP.URL", req->uri.start, req->uri.len);
  }
  for (i = 0; i < h->cnt; i++) {
    const struct head_kv *kv = h->h+i;
    if (0 == kv->key.len || 0 == kv->val.cnt)
      continue;
    if (10 == kv->key.len && 0 == strncasecmp(kv->key.start, "USER-AGENT", 10)) {
      rep_hint("4", ipbuf, "RTSP.User-Agent", kv->val.p[0].start, kv->val.p[0].len);
    } else if (6 == kv->key.len && 0 == strncasecmp(kv->key.start, "SERVER", 6)) {
      rep_hint("4", ipbuf, "RTSP.Server", kv->val.p[0].start, kv->val.p[0].len);
    }
  }
}

/**
 * method dictionary, tied to 'enum RTSP_Method'
 */
static const char *Meth[] = {
  "",
  "DESCRIBE",
  "ANNOUNCE",
  "GET_PARAMETER",
  "OPTIONS",
  "PAUSE",
  "PLAY",
  "RECORD",
  "REDIRECT",
  "SETUP",
  "SET_PARAMETER",
  "XXX" /* Other */
};

int rtsp_is_tcp_port(u16 port)
{
  return RTSP_TCP_PORT     == port
      || RTSP_TCP_PORT_ALT == port;
}

int rtsp_is_udp_port(u16 port)
{
  return RTSP_UDP_PORT     == port
      || RTSP_UDP_PORT_ALT == port;
}

static int init(void)
{
  return 1;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[1024];
} TestCase[] = {
  { 571, "\x52\x54\x53\x50\x2f\x31\x2e\x30\x20\x32\x30\x30\x20\x4f\x4b\x0d\x0a\x54\x72\x61\x6e\x73\x70\x6f\x72\x74\x3a\x20\x52\x54\x50\x2f\x41\x56\x50\x2f\x55\x44\x50\x3b\x75\x6e\x69\x63\x61\x73\x74\x3b\x73\x65\x72\x76\x65\x72\x5f\x70\x6f\x72\x74\x3d\x35\x30\x30\x34\x2d\x35\x30\x30\x35\x3b\x63\x6c\x69\x65\x6e\x74\x5f\x70\x6f\x72\x74\x3d\x32\x34\x36\x32\x2d\x32\x34\x36\x33\x3b\x73\x73\x72\x63\x3d\x39\x32\x37\x37\x31\x37\x64\x65\x3b\x6d\x6f\x64\x65\x3d\x50\x4c\x41\x59\x0d\x0a\x44\x61\x74\x65\x3a\x20\x53\x75\x6e\x2c\x20\x30\x36\x20\x4e\x6f\x76\x20\x32\x30\x30\x35\x20\x31\x32\x3a\x31\x39\x3a\x34\x37\x20\x47\x4d\x54\x0d\x0a\x43\x53\x65\x71\x3a\x20\x32\x0d\x0a\x53\x65\x73\x73\x69\x6f\x6e\x3a\x20\x31\x37\x35\x35\x35\x39\x34\x30\x30\x31\x32\x36\x30\x37\x37\x31\x36\x32\x33\x35\x3b\x74\x69\x6d\x65\x6f\x75\x74\x3d\x36\x30\x0d\x0a\x53\x65\x72\x76\x65\x72\x3a\x20\x57\x4d\x53\x65\x72\x76\x65\x72\x2f\x39\x2e\x31\x2e\x31\x2e\x33\x38\x31\x34\x0d\x0a\x53\x75\x70\x70\x6f\x72\x74\x65\x64\x3a\x20\x63\x6f\x6d\x2e\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x2e\x77\x6d\x2e\x73\x72\x76\x70\x70\x61\x69\x72\x2c\x20\x63\x6f\x6d\x2e\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x2e\x77\x6d\x2e\x73\x73\x77\x69\x74\x63\x68\x2c\x20\x63\x6f\x6d\x2e\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x2e\x77\x6d\x2e\x65\x6f\x73\x6d\x73\x67\x2c\x20\x63\x6f\x6d\x2e\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x2e\x77\x6d\x2e\x66\x61\x73\x74\x63\x61\x63\x68\x65\x2c\x20\x63\x6f\x6d\x2e\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x2e\x77\x6d\x2e\x70\x61\x63\x6b\x65\x74\x70\x61\x69\x72\x73\x73\x72\x63\x2c\x20\x63\x6f\x6d\x2e\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x2e\x77\x6d\x2e\x73\x74\x61\x72\x74\x75\x70\x70\x72\x6f\x66\x69\x6c\x65\x0d\x0a\x4c\x61\x73\x74\x2d\x4d\x6f\x64\x69\x66\x69\x65\x64\x3a\x20\x54\x68\x75\x2c\x20\x32\x30\x20\x4f\x63\x74\x20\x32\x30\x30\x35\x20\x31\x36\x3a\x33\x30\x3a\x31\x31\x20\x47\x4d\x54\x0d\x0a\x43\x61\x63\x68\x65\x2d\x43\x6f\x6e\x74\x72\x6f\x6c\x3a\x20\x78\x2d\x77\x6d\x73\x2d\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x73\x69\x7a\x65\x3d\x38\x34\x34\x35\x37\x2c\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x38\x36\x33\x39\x38\x2c\x20\x6d\x75\x73\x74\x2d\x72\x65\x76\x61\x6c\x69\x64\x61\x74\x65\x2c\x20\x70\x72\x6f\x78\x79\x2d\x72\x65\x76\x61\x6c\x69\x64\x61\x74\x65\x0d\x0a\x45\x74\x61\x67\x3a\x20\x22\x38\x34\x34\x35\x37\x22\x0d\x0a\x0d\x0a" },

}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_RTSP, T->len, T->txt, NULL };
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
  init();
  test();
  return 0;
}
#endif


