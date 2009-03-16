/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * Storm Worm Botnet Traffic
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "ipv4.h"
#include "storm-botnet.h"

static size_t parse (char *, size_t, parse_frame *, const parse_status *);
static size_t dump  (const parse_frame *, int options, FILE *);
static void   report(const botid *, const parse_status *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_StormBotnet = {
  DINIT(id,           PROT_STORMBOTNET),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "Storm"),
  DINIT(propername,   "Storm Worm Botnet Protocol"),
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
  const storm_hdr *h = (storm_hdr *)buf;
  return
       sizeof *h <= len
    && 0xe3 == h->e3
    && (
         /* identify protocol by its various command codes
          * and fixed sizes (where possible) */
         ( /* Announce */ 0x0c == h->code && sizeof *h + sizeof(botid) == len)
      || ( /* Response */ 0x0b == h->code && sizeof *h + sizeof(resp_hdr) <= len) /* variable-length payload */
      /* Unknown command, but fixed-size payloads */
      || (                0x15 == h->code && sizeof *h + 23 == len)
      || (                0x1b == h->code && sizeof *h +  2 == len)
      || (                0x1c == h->code && sizeof *h +  4 == len)
      || (                0x0d == h->code && sizeof *h      == len)
      || (                0x1e == h->code && sizeof *h      == len)
    );
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  const storm_hdr *h = (storm_hdr *)buf;
  /* sanity check packet */
  if (sizeof *h > len)
    return 0;
  /* convert endianness */
  /* FIXME: properly parse some day :-P */
#ifndef TEST
  if (Code_Announce == h->code) {
    const botid *b = (botid *)(buf + sizeof *h);
    report(b, st);
  }
#endif
  return len;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  static const botid B;
  const storm_hdr *h = f->off;
  char hashbuf[sizeof B.hash * 2 + 1];
  size_t len = f->len;
  int bytes = 0;

  bytes += fprintf(out,
    "%s e3=0x%02x code=0x%02x\n",
    Iface_StormBotnet.shortname, h->e3, h->code);
  len -= sizeof *h;

  switch ((enum Code)h->code) {
  case Code_Announce:
  {
    const botid *b = (botid *)((u8 *)h + sizeof *h);
    dump_hash_buf(hashbuf, sizeof hashbuf, b->hash, sizeof b->hash);
    bytes += fprintf(out,
      " hash=0x%s ip=%u.%u.%u.%u port=%hu flag=0x%02x\n",
      hashbuf, b->ip[0], b->ip[1], b->ip[2], b->ip[3], b->port, b->flag);
    len -= sizeof *b;
  }
    break;
  case Code_Resp: /* (possibly) multiple-BotId response */
  {
    const resp_hdr *r = (resp_hdr *)((u8 *)f->off + sizeof *h);
    const botid *b = (botid *)((u8 *)r + sizeof *r);
    unsigned i = 0;
    len -= sizeof *r;
    bytes += fprintf(out, " Resp len=%hu\n", r->len);
    while (len >= sizeof *b) {
      dump_hash_buf(hashbuf, sizeof hashbuf, b->hash, sizeof b->hash);
      bytes += fprintf(out,
        " [%2u] hash=0x%s ip=%u.%u.%u.%u port=%hu flag=0x%02x\n",
        i, hashbuf, b->ip[0], b->ip[1], b->ip[2], b->ip[3], b->port, b->flag);
      len -= sizeof *b;
      b++;
      i++;
    }
  }
    break;
  default:
    break;
  }

  if (len > 0) {
    const u8 *trail = (u8 *)f->off + (f->len - len);
    bytes += fprintf(out, " Trailing: ");
    bytes += dump_bytes((char *)trail, len, out);
    fputc('\n', out);
    bytes++;
  }

  return (size_t)bytes;
}

/**
 * format our
 * @note botid->ip is always 0.0.0.0; because it is easier for the receiver
 * to calculate our external IP than it is for us; so 'ip' is passed from the parse stack
 */
static char * botid_addr(char *dst, size_t dstlen, const botid *b, const u8 *ip)
{
  (void)snprintf(dst, dstlen,
    /* hash */
    "%02x%02x%02x%02x"
    "%02x%02x%02x%02x"
    "%02x%02x%02x%02x"
    "%02x%02x%02x%02x"
    /* ip */
    ":%u.%u.%u.%u"
    /* port */
    ":%hu",
    b->hash[0],  b->hash[1],  b->hash[2],  b->hash[3],
    b->hash[4],  b->hash[5],  b->hash[6],  b->hash[7],
    b->hash[8],  b->hash[9],  b->hash[10], b->hash[11],
    b->hash[12], b->hash[13], b->hash[14], b->hash[15],
    ip[0], ip[1], ip[2], ip[3],
    b->port);
  return dst;
}

static void report(const botid *b, const parse_status *st)
{
  char ipbuf[48],
       botbuf[64];
  const parse_frame *fi = st->frame + st->frames - 2;
  const ipv4 *ip = fi->off;
  assert(PROT_IPv4 == fi->id);
  (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
  rep_addr("4", ipbuf, "Storm", botid_addr(botbuf, sizeof botbuf, b, ip->src), Iface_StormBotnet.shortname, 1);
}


#ifdef TEST

static struct {
  size_t len;
  char txt[1024];
} TestCase[] = {
  {  2, "\xe3\x0d" },
  { 25, "\xe3\x0c\x31\x24\xac\x61\x07\xb6\xf9\xab\xd2\x97\xc8\x2b\xd0\x64\x4f\x09\x00\x00\x00\x00\xfb\x5f\x00" },
  {  6, "\xe3\x1c\x0c\xda\xa4\x4a" },
  {  4, "\xe3\x1b\x98\x7c" },
  { 25, "\xe3\x15\xdc\x70\x9f\xd9\x70\x88\x79\xdd\x70\x81\x22\x65\x48\x80\x4b\x33\x4c\x78\x9d\x5d\x62\x79" },
  { 306,
    "\xe3\x0b\x0d\x00\x40\x47\xcb\xe3\x5d\x9b\x13\x84\x52\x76\x90\x1f\x8c\xe3\x37\xa4\x3a\xba\xb0\x89\x16"
    "\x50\x00\x61\xf6\x17\xa9\x89\xeb\xc1\x99\x3a\x54\x2d\xf9\x47\xdb\x56\xd3\x20\x32\xe8\x3d\x25\x1d\x61"
    "\x20\x97\x12\xfe\x63\x2f\x2b\xab\xfe\x7e\x23\xa9\x18\x2c\xf6\xab\x6c\xa6\x6f\x9d\x49\xf4\xc2\xf3\x63"
    "\xd6\xac\x33\x70\xba\x14\x46\x7c\xf5\x97\x5b\x2b\x3b\x75\x1a\x52\x8d\xb3\x4d\x52\x11\x3d\xdb\x95\x5b"
    "\xbc\x2a\xd2\xa0\xc9\xe3\x6b\xa3\x0c\xd0\xc1\x28\x2f\xe7\xf6\x23\x47\xf3\xce\x06\x1d\xa9\x31\x6a\xcd"
    "\x57\x53\xbc\x72\xdc\x4e\xf5\xc9\x7a\x76\xb4\x15\x4c\x1a\x90\xed\x70\x2e\x4c\xd8\xc5\x85\xdf\x52\x7c"
    "\xf5\xdf\x1d\x53\x34\x23\xe6\x2a\xa3\x1c\x57\xe0\xd7\xc6\x8a\x40\x46\xf1\xa1\xac\xc4\xb4\xb0\x18\xdf"
    "\x82\x0e\x80\x45\xfc\x5d\x71\xf6\xe4\xa1\x09\x48\xf6\x04\x4f\xac\xa4\xe1\x1c\xd4\x55\x53\x93\x1c\xfb"
    "\xea\x24\xa5\x1f\x5d\x95\x15\x04\x13\x43\xf2\x24\x9d\x11\xe2\xe2\x1b\x2c\x5f\x45\xa8\xfb\x57\x5a\xe5"
    "\xbc\x33\x0e\x51\x6d\xad\x21\x5e\x84\x1e\xc5\x10\xc6\x0e\xdf\x32\xb9\xf0\x36\xa0\x4b\xc0\x0a\xf8\xae"
    "\x4c\x51\x0c\xe0\x53\x20\x1f\x3b\x13\xbc\x89\x1f\xdf\xc8\xe2\xf5\x50\xc5\x80\x60\x6f\x30\xe7\x22\x15"
    "\x15\xb8\xbc\x8c\x49\xa4\x2e\x13\xb2\x5a\xd6\x31\x7a\x15\x5b\x5f\xb6\x01\x5b\xdb\xfc\x32\x52\x75\xbf"
    "\x8d\x94\x8f" },
  { 326,
    "\xe3\x0b\x0e\x00\xae\xf3\xec\x90\x40\xba\xa7\x25\xd5\xab\x24\x82\xb2\x00\x80\x74\x79\xf6\x93\x67\x20"
    "\x34\x00\x22\x0f\xdd\xd5\xcf\xe7\x9b\x5d\xe1\x2f\xd9\x0f\x20\xea\xe0\xa6\x8b\xf2\x57\xb9\x05\x28\x61"
    "\xc3\xaa\xe0\x30\xcc\x2a\x3f\xe6\x89\x7f\x14\x56\x6e\x60\x06\x3c\xbf\x4f\x0a\x0c\x03\x15\xc2\x13\x45"
    "\x92\x3d\xe0\xe8\x3f\x6c\x92\x8b\xbd\xea\x3e\xfb\xf1\x3b\x38\x2e\xcc\x8d\x74\x5b\x11\x2f\xaf\xdf\x33"
    "\xac\xbe\x8c\x18\xc7\xa3\x99\xd6\x13\x97\x58\x23\x19\x1e\x73\xe9\x55\xe0\xcf\xe3\x2c\x8d\xbc\x70\xbd"
    "\x93\x79\xb2\xfc\x5a\x77\x33\x3d\x36\xa3\x98\x60\xd9\x29\x8c\xfc\x70\x21\x3c\x4c\xbb\xb4\x18\xfa\xac"
    "\x0e\x2b\xf5\x81\x6a\xd6\x20\x7e\x56\xe3\x34\xb5\x13\xbe\x8b\x43\x92\x40\xa1\x4a\x84\xc3\xac\xa7\xe4"
    "\x8a\x00\x51\xbd\xcb\x88\xd4\x02\x5a\x3b\x51\x5d\xf6\xf5\xb9\x20\x9e\x1e\xbd\x10\xa5\x5a\xdc\xd3\xf0"
    "\xd8\xb2\x47\x62\x3d\x51\x71\x02\xc8\x4c\xf3\xdb\xf1\xac\x70\x47\xff\xce\x39\x1d\x6d\xed\xe3\xeb\x13"
    "\x8d\xd6\x38\x01\x7a\x7b\xe4\x24\x84\x1d\x70\x85\xea\x1a\x2c\x5c\x36\x79\x35\x16\xab\xb9\xf1\x52\xeb"
    "\xea\x65\xaa\x98\xa7\x1c\x1f\xc5\x6a\x79\x16\xbd\x0f\x4b\x84\x35\x57\x37\x42\xef\xb5\xa0\xe3\x56\xb7"
    "\x9f\xcf\x1e\xc8\x48\xa4\xc8\x2b\x35\x53\x62\xf6\x13\xea\xb2\xb2\x69\xa8\x7a\x79\xe9\x09\x4e\x0f\x56"
    "\xfb\xe2\x8d\x91\x98\x7c\x29\xa4\x85\xad\xef\xc8\x10\x33\xb2\x3e\x27\xaf\xe9\x02\x9a\x05\xf7\x42\xda"
    "\xff" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_STORMBOTNET, T->len, T->txt, NULL };
    printf("#%2u: ", i);
    dump_bytes(T->txt, T->len, stdout);
    fputc('\n', stdout);
    assert(1 == test_udp(T->txt, T->len, NULL) && "Ensure my valid test data passes my tests!");
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



