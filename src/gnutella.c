/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Gnutella
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
#include "tcp.h"
#include "http.h"
#include "gnutella.h"

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump (const parse_frame *, int options, FILE *);

static int test_ports   (const char *, size_t, const parse_status *);
static int test_header  (const char *, size_t, const parse_status *);
static int test_bin_huer(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_TCP, test_ports    },
  { PROT_TCP, test_header   },
  { PROT_TCP, test_bin_huer }
};

/**
 * exported interface
 */
const prot_iface Iface_Gnutella = {
  DINIT(id,           PROT_GNUTELLA),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "Gnutella"),
  DINIT(propername,   "Gnutella"),
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
 * test TCP for well-known Gnutella port numbers.
 */
static int test_ports(const char *buf, size_t len, const parse_status *st)
{
  const tcp *t = st->frame[st->frames-1].off;
  return GNUTELLA_TCP_PORT  == t->srcport
      || GNUTELLA_TCP_PORT  == t->dstport
      || GNUTELLA_TCP_PORT2 == t->srcport
      || GNUTELLA_TCP_PORT2 == t->dstport;
}

/**
 * test 'buf' for the beginnings of HTTP-based GNUTELLA protocol content
 */
static int test_header(const char *buf, size_t len, const parse_status *st)
{
  char c[32]; /* temp sscanf buffers */
  unsigned i;
  return len >= 32                          /* minimum possible valid length */
      && 'G' == buf[0]                      /* cheap initial test */
      && memcspn(buf, len, "\r\n", 2) < len /* contains a newline somewhere */
      && (                                  /* validate header line */
        3 == sscanf(buf, "GNUTELLA %31[^ /]/%u.%u\r\n", c, &i, &i) ||
        4 == sscanf(buf, "GNUTELLA/%u.%u %u %31[^\r\n]\r\n", &i, &i, &i, c)
      );
}

static struct {
  enum Type type;
  const char *name;
  size_t minbytes;
} PerType[Type_COUNT] = {
  { Type_Ping,  "ping", 0             },
  { Type_Pong,  "pong", sizeof(pong)  },
  { Type_Bye,   "bye",  sizeof(bye)   }
};

static size_t type_minbytes(u8 type)
{
  size_t bytes = 0;
  if (type < sizeof PerType / sizeof PerType[0])
    bytes = PerType[type].minbytes;
  return bytes;
}

static int guid_is_modern(const u8 *guid);
static int msgtype_is_known(u8 type);
static int ttl_hops_makes_sense(u8 ttl, u8 hops);
static int payload_len_conforms(u16 len);

/**
 * test 'buf' for the contents of a binary Gnutella header
 * via hueristics based on the header fields
 */
static int test_bin_huer(const char *buf, size_t len, const parse_status *st)
{
  const gnut_hdr *h = (gnut_hdr *)buf;
  return len >= sizeof *h
      && guid_is_modern(h->guid)
      && msgtype_is_known(h->type)
      && ttl_hops_makes_sense(h->ttl, h->hops)
      && payload_len_conforms(ltohs(h->payload_len))
      && ltohs(h->payload_len) <= type_minbytes(h->type);
}

static void report(const parse_status *, const parse_frame *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
/* FIXME: http_parse does not currently handle this:
 *
 * Headers follow the standards described in RFC822 and RFC2616.  Each
 * header is made of a field name, followed by a colon, and then the 
 * value.  Each line ends with the  sequence, and the end of the
 * headers is marked by a single  line.  Each line normally 
 * starts a new header, unless it begins with a space or an horizontal 
 * tab (ASCII codes 32 and 9 in decimal, respectively), in which case it
 * continues the preceding header line.  The extra spaces and tabs may 
 * be collapsed into a single space as far as the header value goes.  
 * For instance:
 * 
 *   First-Field: this is the value of the first field
 *   Second-Field: this is the value
 *       of the
 *       second field
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  static gnutella g;
  size_t bytes;
  memset(&g, 0, sizeof g);
  bytes = http_parse(buf, len, f, st, &g.h);
  f->pass = &g;
#ifndef TEST
  report(st, f);
#endif
  return bytes;
}

static size_t dump(const parse_frame *f, int opt, FILE *out)
{
  const gnutella *g = f->pass;
  return http_dump(f, opt, out, &g->h, Iface_Gnutella.shortname);
}

static void report(const parse_status *st, const parse_frame *f)
{
  char ipbuf[48];
  const gnutella *g = f->pass;
  const http_req *r = &g->h.data.req;
  const http_headers *h = &r->headers;
  const parse_frame *fi = st->frame + st->frames - 2;
  const ipv4 *ip = fi->off;
  unsigned i;
  if (PROT_IPv4 == fi->id) {
    (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
    for (i = 0; i < h->cnt; i++) {
      const struct head_kv *kv = h->h+i;
      if (10 == kv->key.len && 0 == strncasecmp(kv->key.start, "User-Agent", 10)) {
        rep_hint("4", ipbuf, "Gnutella.User-Agent", kv->val.p[0].start, kv->val.p[0].len);
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
  /* initialize the higher, irregularly-spaced type code entries... */
  
  PerType[Type_Push].type         = Type_Push;
  PerType[Type_Push].name         = "push";
  PerType[Type_Push].minbytes     = sizeof(push);
  
  PerType[Type_Query].type        = Type_Query;
  PerType[Type_Query].name        = "query";
  PerType[Type_Query].minbytes    = sizeof(qry);
  
  PerType[Type_QueryHit].type     = Type_QueryHit;
  PerType[Type_QueryHit].name     = "query-hit";
  PerType[Type_QueryHit].minbytes = sizeof(qryhit);

  return 1;
}

/**
 * @ref #2 S2.2.1
 *
 * Servents SHOULD store all 1's (0xff) in byte 8 of the
 * GUID.  (Bytes are numbered 0-15, inclusive.) This 
 * serves to tag the GUID as being from a modern 
 * servent.
 *
 * Servents SHOULD initially store all 0's in byte 15 of
 * the GUID. This is reserved for future use.
 *
 * The other bytes SHOULD have random values.
 *
 */
static int guid_is_modern(const u8 *guid)
{
  return 0xff == guid[7]
      && 0x00 == guid[15];
}

/**
 * 'type' is an identifiable msgtype
 */
static int msgtype_is_known(u8 type)
{
  /* NOTE: ordered in likelihood of appearance */
  return Type_Query    == type
      || Type_Ping     == type
      || Type_Pong     == type
      || Type_Bye      == type
      || Type_QueryHit == type
      || Type_Push     == type;
}

/**
 * @ref #2 
 *    The number of times the message has been forwarded.
 *    As a message is passed from servent to servent, the
 *    TTL and Hops fields of the header must satisfy the 
 *    following condition:
 *    TTL(0) = TTL(i) + Hops(i)
 *    Where TTL(i) and Hops(i) are the value of the TTL and
 *    Hops fields of the message, and TTL(0) is maximum 
 *    number of hops a message will travel (usually 7).
 */
static int ttl_hops_makes_sense(u8 ttl, u8 hops)
{
#define MAX_TTL0 16
  return MAX_TTL0 >= ttl /* both values are sufficiently low */
      && MAX_TTL0 >= hops
      && MAX_TTL0 >= ttl + hops /* the total is sufficiently low */
      && (ttl & hops); /* can't both be zero */
}

/**
 *
 * Payload Length
 *   The length of the message immediately following 
 *   this header. The next message header is located 
 *   exactly this number of bytes from the end of this 
 *   header i.e. there are no gaps or pad bytes in the 
 *   Gnutella data stream. Messages SHOULD NOT be larger
 *   than 4 kB.
 */
static int payload_len_conforms(u16 len)
{
  return len <= 4096;
}


#ifdef TEST

static struct {
  size_t len;
  char txt[512];
} TestCase[] = {
  { 0,
    "GNUTELLA CONNECT/0.6\r\n"
    "User-Agent: BearShare/1.0\r\n"
    "Pong-Caching: 0.1\r\n"
    "GGEP: 0.5\r\n"
    "\r\n" },
  { 0,
    "GNUTELLA/0.6 200 OK\r\n"
    "User-Agent: BearShare/1.0\r\n"
    "Pong-Caching: 0.1\r\n"
    "GGEP: 0.5\r\n"
    "Private-Data: 5ef89a\r\n"
    "\r\n" },
  { 0,
    "GNUTELLA/0.6 200 OK\r\n"
    "Private-Data: a04fce\r\n"
    "\r\n" },
  { 10,
    "Binary(\x00\x01\x02)" },
  { 0,
    "GNUTELLA CONNECT/0.6\r\n"
    "User-Agent: LimeWire/1.0\r\n"
    "X-Ultrapeer: False\r\n"
    "X-Query-Routing: 0.1\r\n"
    "\r\n" },
  { 0,
    "GNUTELLA/0.6 200 OK\r\n"
    "User-Agent: LimeWire/1.0\r\n"
    "X-Ultrapeer: True\r\n"
    "X-Ultrapeer-Needed: False\r\n"
    "X-Query-Routing: 0.1\r\n"
    "X-Try: 24.37.144:6346, 193.205.63.22:6346\r\n"
    "X-Try-Ultrapeers: 23.35.1.7:6346, 18.207.63.25:6347\r\n"
    "\r\n" },
  { 0,
    "GNUTELLA/0.6 200 OK\r\n"
    "\r\n" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    size_t len = T->len ? T->len : strlen(T->txt);
    parse_frame pf = { PROT_GNUTELLA, len, T->txt, NULL };
    printf("#%2u: ", i);
    dump_chars(T->txt, len, stdout);
    fputc('\n', stdout);
    parse(T->txt, len, &pf, NULL);
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

