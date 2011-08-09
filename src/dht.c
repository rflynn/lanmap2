/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2011 Ryan Flynn
 * All rights reserved.
 */
/*
 * Distributed Hash Table
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "dht.h"

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
const prot_iface Iface_DHT = {
  DINIT(id,           PROT_DHT),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "DHT"),
  DINIT(propername,   "DHT"),
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

/*
 * DHT Queries <URL: http://www.bittorrent.org/beps/bep_0005.html#dht-queries>
 * ping
 *   query len=56 d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe
 *   response len=47 d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re
 *
d1:ad2:id20:dd\x7f\x09\x85G\x1c\x068M\xb79/\x82j\x82\xe7\xe0\xb6je1:q4:ping1:t4:pn\x00\x001:v4:TR#\x9d1:y1:qe
 * find_node
 *   query len=92 d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe
 *   response len=65 d1:rd2:id20:0123456789abcdefghij5:nodes9:def456...e1:t2:aa1:y1:re
 * get_peers
 *   query len=95 d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe
 *   response len=82 d1:rd2:id20:abcdefghij01234567895:nodes9:def456...5:token8:aoeusnthe1:t2:aa1:y1:re
 * announce_peer
 *   query len=129 d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe
 *   response len=47 d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re
 *
UDP BITTORRENT DHT: is_dht=0 len=67 buf=d1:ad2:id20:dd\x7f\x09\x85G\x1c\x068M\xb79/\x82j\x82\xe7\xe0\xb6je1:q4:ping1:t4:pn\x00\x001:v4:TR#\x9d1:y1:qe
UDP BITTORRENT DHT: is_dht=0 len=58 buf=d1:rd2:id20:mO\xe2\x972\xccm\x1fy\x81 IF\x80\x9d\x02\xb19q\xdee1:t4:pn\x00\x001:v4:UT\\xde1:y1:re
UDP BITTORRENT DHT: is_dht=0 len=277 buf=d1:rd2:id20:dd\x7f\x09\x85G\x1c\x068M\xb79/\x82j\x82\xe7\xe0\xb6j5:nodes208:dm\xb7\xda\xad\xda\xb8\xb7\xf6\xd2\x08\xa5\x8d5\xbbm\xc8\x9e\xd9\xa8Fqhh\xe1\xf7dl\xa3\x0a8\xcd\xc5j\x05\xbf\x9e\xcdUu\x1a\x0e\x00'b\xc4MN\xb4"\xacIdl\x83\x16\xd2\x1e\x19\xae\xd462I\xc6\x02\x93\x86\xcc<\x8a\x9e<\x0d\x81\x0a1\xcfdlK\xbdi\xd0\x06\x0f#\xcc\xd1\xb6\\xd7\xd3\x85\xab\xf7\x8aWc{\xb4\x08T#dn\x8f\xefS,\x987F\xf1$\xc0\x8by\x96\xfc\xb4\x7f\xce\xa1_\x18\xdb\xb5l\xf9dn)\x94\x1f\xa3\xc1\x034wrS\xb1\xf4I\x02\x04\xb7'\xcbatp\xbb\x1a\xc5dn/\x823\xd4\xca\x8b\xcd,\x8f\x12\xf3\xc2\xeb\xe2\x18\xd5sJMFfP\xd9\x05dh\xbd\x10\xd7/N\xe7\xedZ\xc2\xf2\xdb\xa3\xf9[\xb6\x10\xef\xffb\x94\xf2D)\xf1e1:t4:"\xc2\xeb\xa01:v4:TR#\x9d1:y1:re
UDP BITTORRENT DHT: is_dht=0 len=58 buf=d1:rd2:id20:mO\xe2\x972\xccm\x1fy\x81 IF\x80\x9d\x02\xb19q\xdee1:t4:pn\x00\x001:v4:UT\\xde1:y1:re
UDP BITTORRENT DHT: is_dht=0 len=94 buf=d1:ad2:id20:\x07\xe5\x17S\x9a\x0c\xea\x80a\xd3\x1ax\xb8de\x89\xac\xd1\xb809:info_hash20:d\x131\x87\xa3\x9brt\x0aRT\xefd\x00n\\x86\x99\xae7e1:q9:get_peers1:t1:W1:y1:qe
 *
 */
static int test_udp(const char *buf, size_t len, const parse_status *st)
{
  int is_dht = len >= 47
      && (
          /* query/response prefix */
          (0 == memcmp("d1:ad2:id20:", buf, 12) ||
           0 == memcmp("d1:rd2:id20:", buf, 12))
      );
#if 0 /* DEBUG */
  printf("UDP BITTORRENT DHT: is_dht=%d len=%zu buf=", is_dht, len);
  dump_chars(buf, len, stdout);
  printf("\n");
#endif
  return is_dht;
}

static size_t do_parse(const char *, size_t, parse_frame *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  size_t bytes;
  bytes = do_parse(buf, len, f);
  return bytes;
}

/*
 * parse tlv [len] ':' [value] into ptrlen p
 * on error return 0
 *
 * TODO: currently we parse list values l...e correctly, but we only *retain* the last item
 *
 * d ... e (datum?)
 * l ... e (list)
 * len=109 d1:rd2:id20:dd\x7f\x09\x85G\x1c\x068M\xb79/\x82j\x82\xe7\xe0\xb6j5:token8:\x082\x1d:oM\xce?6:valuesl6:m\xa5;\xf6~\x866:\xbc\xe3\x14\xbb\xee\xea6:]Q\xa3\xe8\xe1}ee1:t4:\x18\xc1\x87%1:v4:TR#\x9d1:y1:re
 * len=137 d1:rd2:id20:dd\x7f\x09\x85G\x1c\x068M\xb79/\x82j\x82\xe7\xe0\xb6j5:token8:b5]b\x1f.:,6:valuesl6:OdR.&\x866:_*W\xb9le6:MU\xa7\xb8\x1dR6:O\x84\x0d\x9f2\xeb6:S\xe44\x83<{6:^\x9c\xa0\xe4/\xb0ee1:t8:,zm\xae\xb01\xf9R1:v4:TR#\x9d1:y1:re
 * 
 */
static size_t do_parse_tlv(const char *buf, size_t len, ptrlen *p)
{
  const char *b = buf;
  /* FIXME: force '\0' at the end of the string or we could all offff argh.... */
  int need_e = *b == 'l';
  if (need_e)
    b++, len--;
  do {
    char *curr = NULL;
    unsigned long l = strtoul(b, &curr, 10);
    if (ULONG_MAX == l || 0 == l || !curr || curr <= b || curr >= b+len)
      return 0;
    len -= curr - b;
    if (*curr != ':')
      return 0;
    curr++, len--;
    if (len < l)
      return 0;
    p->start = curr;
    p->len = (unsigned)l;
#if 1
    fprintf(stdout, "%s:%u parsed len=%u start=", __func__, __LINE__, p->len);
    dump_chars(p->start, p->len, stdout);
    fputc('\n', stdout);
#endif
    b = curr + l;
  } while (need_e && *b != 'e' && len);
  if (need_e && *b == 'e')
    b++;
  return (size_t)(b - buf);
}

static size_t do_parse_args(const char *buf, size_t len, dht_pkt *p)
{
  ptrlen_list *args = &p->args;
  unsigned i = 0, max = sizeof args->p / sizeof args->p[0];
  const char *orig = buf;
  if (len >= 4 && (0 == memcmp("d1:rd", buf, 5) || 0 == memcmp("d1:ad", buf, 5))) {
    size_t b;
    p->ar.start = (char*)buf+3;
    p->ar.len = 1;
    buf += 5, len -= 5; /* skip header to args */
    while (i < max && (b = do_parse_tlv(buf, len, args->p+i)))
      i++, buf += b, len -= b;
  }
  p->args.cnt = i;
  return (size_t)(buf-orig);
}

static size_t do_parse_hdr(const char *buf, size_t len, dht_pkt *p)
{
  ptrlen kv[2];
  unsigned i = 0;
  size_t b, total = 0;
  if (len && 'e' == *buf) {
    buf++, len--;
    while ((b = do_parse_tlv(buf, len, kv+(i%2)))) {
      if (i % 2) {
        switch (kv[0].start[0]) {
        case 't': p->t = kv[1]; break;
        case 'y': p->y = kv[1]; break;
        case 'q': p->q = kv[1]; break;
        default:                break;
        }
      }
      i++, buf += b, len -= b, total += b;
    }
  }
  return total;
}

static void dht_pkt_init(dht_pkt *p)
{
  p->t.start = p->y.start = p->q.start = p->ar.start = 0;
  p->t.len = p->y.len = p->q.len = p->ar.len = 0;
  p->args.cnt = 0;
}

static dht_pkt Dht;
static size_t do_parse(const char *buf, size_t len, parse_frame *f)
{
  size_t used;
  dht_pkt_init(&Dht);
#if 1
  printf("len=%zu ", len);
  dump_chars(buf, len, stdout);
  fputc('\n', stdout);
#endif
  used = do_parse_args(buf, len, &Dht);
#if 1
  fprintf(stdout, "%s:%u used=%zu\n", __func__, __LINE__, used);
  dump_chars(buf, used, stdout);
  fputc('\n', stdout);
  fprintf(stdout, "%s:%u togo=", __func__, __LINE__);
  dump_chars(buf+used, len-used, stdout);
  fputc('\n', stdout);
#endif
  if (used) {
    if (used >= len)
      used = 0;
    else
      used += do_parse_hdr(buf+used, len-used, &Dht);
    f->pass = &Dht;
  }
#if 0
  fprintf(stdout, "%s:%u used=%zu\n", __func__, __LINE__, used);
#endif
  return used;
}

/*
 * dump UDP DHT (distributed hash table) packets
 */
static size_t dump(const parse_frame *f, int options, FILE *out)
{
  static char vbuf[1024];
  const dht_pkt *p = f->pass;
  int bytes = fprintf(out, "DHT");
  if (p->q.len) {
    dump_chars_buf(vbuf, sizeof vbuf, p->q.start, p->q.len);
    bytes += fprintf(out, " %s", vbuf);
  }
  dump_chars_buf(vbuf, sizeof vbuf, p->y.start, p->y.len);
  bytes += fprintf(out, " %s", vbuf);
  dump_chars_buf(vbuf, sizeof vbuf, p->t.start, p->t.len);
  bytes += fprintf(out, " txn=%s", vbuf);
  {
    unsigned i;
    for (i = 0; i+1 < p->args.cnt; i+=2) {
      dump_chars_buf(vbuf, sizeof vbuf, p->args.p[i].start, p->args.p[i].len);
      bytes += fprintf(out, " %s=", vbuf);
      dump_chars_buf(vbuf, sizeof vbuf, p->args.p[i+1].start, p->args.p[i+1].len);
      bytes += fprintf(out, "%s", vbuf);
    }
  }
  fputc('\n', out), bytes++;
  return (size_t)bytes;
}

static int init(void)
{
  return 1;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[256];
} TestCase[] = {

}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_DHT, T->len, T->txt, NULL };
    size_t consumed;
    printf("#%2u: ", i);
#if 0
    dump_chars(T->txt, T->len, stdout);
#endif
    fputc('\n', stdout);
    consumed = parse(T->txt, T->len, &pf, NULL);
    assert(consumed == T->len);
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

