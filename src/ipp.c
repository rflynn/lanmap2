/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2010-2011 Ryan Flynn
 * All rights reserved.
 */
/*
 * IPP - Internet Printing Protocol
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "prot.h"
#include "util.h"
#include "udp.h"
#include "ipp.h"
#include "ipv4.h"
#include "report.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_IPP = {
  DINIT(id,           PROT_IPP),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "IPP"),
  DINIT(propername,   "Internet Printing Protocol"),
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

static int test_udp(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = st->frame[st->frames-1].off;
  return len > 5
      && IPP_UDP_PORT == u->dstport
      && IPP_UDP_PORT == u->srcport;
}

/*
 * parse and consume non-whitespace and trailing whitespace
 */
static ptrdiff_t nextfield(const char *buf, size_t len, ptrlen *f)
{
  size_t l = memcspn(buf, len, " \r\n", 3);
  f->start = (char*)buf;
  f->len = l;
  buf += l, len -= l;
  l = memspn(buf, len, " ", 1);
  return (buf + l) - f->start;
}

/*
 * parse and consume "quoted string" and trailing whitespace
 * TODO: are leading and trailing quotes always there?
 */
static ptrdiff_t nextstring(const char *buf, size_t len, ptrlen *f)
{
  const char *obuf = buf;
  size_t l;
  if (len && *buf == '"')
    buf++, len--;
  f->start = (char*)buf;
  l = memcspn(buf, len, "\"\r\n", 3);
  f->len = l;
  buf += l, len -= l;
  l = memspn(buf, len, "\" ", 2);
  return (buf + l) - obuf;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  static ipp i;
  const size_t olen = len;
  ptrdiff_t off;
  off = nextfield (buf, len, &i.type);  buf += off, len -= off;
  off = nextfield (buf, len, &i.state); buf += off, len -= off;
  off = nextfield (buf, len, &i.uri);   buf += off, len -= off;
  off = nextstring(buf, len, &i.loc);   buf += off, len -= off;
  off = nextstring(buf, len, &i.info);  buf += off, len -= off;
  off = nextstring(buf, len, &i.make);  buf += off, len -= off;
  /* the rest */
  i.extra.start = buf;
  i.extra.len = memcspn(buf, len, "\"\r\n", 3);
  f->pass = &i;
  /* TODO: reports:
   * - extract host from uri, report host as a printer
   * - associate make with host
   * - associate info with host, maybe
   */
#ifndef TEST
  {
    const parse_frame *fi = st->frame + st->frames - 2;
    if (PROT_IPv4 == fi->id) {
      char ipbuf[48],
           locbuf[64];
      size_t loclen = i.loc.len < sizeof locbuf ? i.loc.len : sizeof locbuf - 1;
      const ipv4 *ip = fi->off;
      (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
      memcpy(locbuf, i.loc.start, loclen);
      locbuf[loclen] = '\0';
      rep_addr("4", ipbuf, "CUPS", locbuf, "CUPS.Location", 1);
    }
  }
#endif
  return olen;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const ipp *i = f->pass;
  int bytes = fprintf(out,
    "%s type=%.*s state=%.*s uri=%.*s loc=\"%.*s\" info=\"%.*s\" make=\"%.*s\" extra=\"%.*s\"\n",
    Iface_IPP.shortname,
    (int)i->type.len,  i->type.start, 
    (int)i->state.len, i->state.start, 
    (int)i->uri.len,   i->uri.start, 
    (int)i->loc.len,   i->loc.start, 
    (int)i->info.len,  i->info.start,
    (int)i->make.len,  i->make.start,
    (int)i->extra.len, i->extra.start);
  return (size_t)bytes;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[128];
} TestCase[] = {
  { 182, "b00e 3 ipp://192.168.1.106:631/printers/EPSON_Stylus_Photo_1400 \"User Name\xe2\x80\x99s iMac (3)\" "
         "\"EPSON Stylus Photo 1400\" \"EPSON SP 1400 Series (2)\" job-sheets=none,none lease-duration=300\x0a" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_IPP, T->len, T->txt, NULL };
    printf("#%2u: ", i);
    dump_chars(T->txt, T->len, stdout);
    fputc('\n', stdout);
    parse(T->txt, T->len, &pf, NULL);
    dump(&pf, 0, stdout);
    T++;
  }
}

int main(void)
{
  test();
  return 0;
}
#endif


