/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * rasadv
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "ipv4.h"
#include "udp.h"
#include "rasadv.h"

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump (const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_RASADV = {
  DINIT(id,           PROT_RASADV),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "RASADV"),
  DINIT(propername,   "Routing and Remote Access Server Advertisement"),
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

/* rasadv destination IP address always 239.255.2.2 */
#ifdef __BIG_ENDIAN
# define RASADV_IP 0x0202ffefUL
#else
# define RASADV_IP 0xefff0202UL
#endif

static int test_udp(const char *buf, size_t len, const parse_status *st)
{
  const ipv4 *i = st->frame[st->frames-2].off;
  const udp  *u = st->frame[st->frames-1].off;
  return RASADV_UDP_PORT == u->dstport
      && PROT_IPv4 == st->frame[st->frames-2].id
      && RASADV_IP == *(u32 *)i->dst;
}

static size_t do_parse(char *buf, size_t len, parse_frame *);
static size_t do_dump_report(const struct kv_list *, FILE *);

static void report(const parse_frame *, const parse_status *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  size_t bytes;
  /* sanity check packet */
  if (0 == len)
    return 0;
  bytes = do_parse(buf, len, f);
  if (f->pass)
    report(f, st);
  return bytes;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  int bytes = fprintf(out, "%s\n", Iface_RASADV.shortname);
  bytes += do_dump_report(f->pass, out);
  return (size_t)bytes;
}

/**
 * consume a single token of the pattern "[^;]*;", write it's start and 
 * length in 'p' and return the total number of bytes consumed
 */
static size_t do_parse_token(char *buf, size_t len, ptrlen *p)
{
  size_t bytes;
  p->start = buf;
  bytes = memcspn(buf, len, "=\x0a\x00", 3);
  p->len = bytes;
  if (bytes < len)
    bytes++;
  return bytes;
}

/**
 * rasadv is a simple list of [ token '=' token '\n' ] terminated by \0
 */
static size_t do_parse(char *buf, size_t len, parse_frame *f)
{
  static struct kv_list kvl;
  const char *orig = buf,
             *end  = buf + len;
  struct kv *k = kvl.kv;
  f->pass = &kvl;
  kvl.cnt = 0;
  while (buf < end && len > 0 && kvl.cnt < sizeof kvl.kv / sizeof kvl.kv[0]) {
    size_t l;
    l = do_parse_token(buf, len, &k->key);
    buf += l, len -= l;
    if (l < 2)
      break;
    l = do_parse_token(buf, len, &k->val);
    if (l > 0)
      buf[l-1] = '\0'; /* string-ize */
    buf += l, len -= l;
    kvl.cnt++;
    k++;
  }
  return (size_t)(buf - orig);
}

static size_t do_dump_report(const struct kv_list *l, FILE *out)
{
  int bytes;
  unsigned i;
  for (i = 0; i < l->cnt; i++)
    bytes += fprintf(out, "  %-9.*s %.*s\n",
      l->kv[i].key.len, l->kv[i].key.start,
      l->kv[i].val.len, l->kv[i].val.start);
  return (size_t)bytes;
}

static void report(const parse_frame *f, const parse_status *st)
{
#ifndef TEST
  if (st->frames >= 3) {
    char ipbuf[48];
    const parse_frame *fi = st->frame+st->frames-2;
    const ipv4 *ip = fi->off;
    const struct kv_list *l = f->pass;
    assert(PROT_IPv4 == fi->id);
    (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
    unsigned i;
    for (i = 0; i < l->cnt; i++) {
      if (8 == l->kv[i].key.len && 0 == memcmp("Hostname", l->kv[i].key.start, 8)) {
        rep_addr("4", ipbuf, "RAS", l->kv[i].val.start, Iface_RASADV.shortname, 1);
      } else if (6 == l->kv[i].key.len && 0 == memcmp("Domain", l->kv[i].key.start, 6)) {
        rep_hint("4", ipbuf, "RAS.Domain", l->kv[i].val.start, l->kv[i].val.len);
      }
    }
  }
#endif
}

static int init(void)
{
  printf("RASADV_IP=0x%08lx inet_addr(239.255.2.2)=0x%08lx\n",
    RASADV_IP, (unsigned long)inet_addr("239.255.2.2"));
  assert(RASADV_IP == inet_addr("239.255.2.2"));
  return 1;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[39];
} TestCase[] = {
  { 38, "Hostname=Saleslogix\x0a""Domain=EARTH.COM\x0a\x00" },
  { 20, "Hostname=Saleslogix\x0a" },
  { 19, "Hostname=Saleslogix" },
  {  9, "Hostname=" },
  {  8, "Hostname" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_RASADV, T->len, T->txt, NULL };
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
  init();
  test();
  return 0;
}
#endif

