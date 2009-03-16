/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * TivoConnect Discovery Protocol
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h> /* memcmp */
#include <strings.h> /* strcasecmp */
#include <stdlib.h> /* bsearch */
#include "env.h"
#include "types.h"
#include "report.h"
#include "util.h"
#include "prot.h"
#include "ipv4.h"
#include "tivoconn.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_TiVoConn = {
  DINIT(id,           PROT_TIVOCONN),
  DINIT(osi,          OSI_Trans),
  DINIT(shortname,    "TiVoConn"),
  DINIT(propername,   "TiVoConnect Discovery Protocol"),
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
  const tivoconn *t = (tivoconn *)buf;
  return len > sizeof *t
      && '=' == t->eq[0]
      && ('t' == t->tivoconnect[0] || 'T' == t->tivoconnect[0])
      && 0 == strncasecmp((char*)t->tivoconnect, (char*)"TIVOCONNECT",
                          sizeof t->tivoconnect);
}

static const ptrlen KeyStr[Key_COUNT] = {
  { "",              0 },
  { "identity",      8 },
  { "machine",       7 },
  { "method",        6 },
  { "platform",      8 },
  { "services",      8 },
  { "tivoconnect",  11 },
};

static enum Key str2key(const ptrlen *p)
{
  unsigned i;
  enum Key k = Key_Unknown;
  for (i = 0; i < Key_COUNT; i++) {
    if (KeyStr[i].len == p->len &&
        KeyStr[i].start[0] == p->start[0] &&
        0 == memcmp(KeyStr[0].start, p->start, p->len))
      break;
  }
  if (i < Key_COUNT)
    k = (enum Key)i;
  return k;
}

/**
 * parse a single line of the TivoConnect protocol into a 'kkv' structure
 * "foo=bar\x0a"
 * "AAABCCCDDDD"
 */
static ptrdiff_t do_parse_kv(char *buf, size_t len, kkv *k)
{
  const char *orig = buf; /* save original address */
  size_t l = memcspn(buf, len, "=\x0a", 2);
  k->keystr.start = buf;
  k->keystr.len = l;
  strlower(k->keystr.start, k->keystr.len);
  k->key = str2key(&k->keystr);
  buf += l, len -= l;
  l = memspn(buf, len, "=", 1);
  buf += l, len -= l;
  k->val.start = buf;
  l = memcspn(buf, len, "\x0a", 1);
  k->val.len = l;
  buf += l, len -= l;
  l = memspn(buf, len, "\x0a", 1);
  buf += l, len -= l;
  return buf - orig;
}

static ptrdiff_t do_parse(char *buf, size_t len, tivoconn_kv *kv)
{
  const char *orig = buf;
  size_t bytes;
  kv->cnt = 0;
  do {
    bytes = do_parse_kv(buf, len, kv->item + kv->cnt);
    assert(bytes <= len);
    if (bytes)
      kv->cnt++;
    buf += bytes;
    len -= bytes;
  } while (bytes && len &&
           kv->cnt < sizeof kv->item / sizeof kv->item[0]);
  return buf - orig;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  tivoconn *t = (tivoconn *)buf;
  static tivoconn_kv kv;
  size_t parsed;
  /* sanity check packet */
  /* convert endianness */
  /* parse */
  parsed = do_parse(buf, len, &kv);
  f->pass = &kv;
  return len; /* consume all bytes */
}

size_t dump(const parse_frame *f, int options, FILE *out)
{
  const tivoconn *t = (tivoconn *)f->off;
  const tivoconn_kv *kv = f->pass;
  const char *ver = (char *)f->off + sizeof t->tivoconnect + 1;
  int bytes = fprintf(out, "%s ver=%c\n", Iface_TiVoConn.shortname, *ver);
  unsigned i;
  for (i = 1; i < kv->cnt; i++) { /* yes, start at one. skip TiVoConn header */
    bytes += fprintf(out, " %-8.*s %.*s\n",
      kv->item[i].keystr.len, kv->item[i].keystr.start,
      kv->item[i].val.len, kv->item[i].val.start);
    if (Key_Platform == i) {
      char ipbuf[48];
      const parse_frame *fi = f-2;
      const ipv4 *ip = fi->off;
      assert(PROT_IPv4 == fi->id);
      (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
      rep_hint("4", ipbuf, "TivoConn.Platform", kv->item[i].val.start, kv->item[i].val.len);
    }
  }
#if 0
  bytes += dump_chars(ver + 2, f->len - ((ver + 2) - (char *)f->off), stdout);
  fputc('\n', stdout);
  bytes++;
#endif
  return (size_t)bytes;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

