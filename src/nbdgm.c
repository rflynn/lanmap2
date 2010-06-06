/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * NetBIOS Datagram
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "udp.h"
#include "ipv4.h"
#include "nbdgm.h"

static const nb_dgm Dgm;
static const nb_dgm_name DgmName;
static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_NBDgm = {
  DINIT(id,           PROT_NBDGM),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "NB-Dgm"),
  DINIT(propername,   "NetBIOS Datagram"),
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
 * Windows NB Dgms are sent between reserved ports on both machines (TODO: Reference needed)
 */
static int test_udp(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = (udp *)st->frame[st->frames - 1].off;
  return NBDGM_UDP_PORT == u->srcport &&
         NBDGM_UDP_PORT == u->dstport;
}

/**
 * Each octet in a NetBIOS name is split into 4-bit nibbles and stored as
 * an uppercase ASCII character 'A' + n
 * @ref #2
 */
size_t nb_decode_name(char *wr, size_t wrlen, const char *rd, size_t rdlen)
{
  const char *owr = wr;
  assert((unsigned)rdlen < 2048);
  assert(wrlen >= rdlen / 2);
  if (0 == (rdlen & 1)) {
    while (rdlen -= 2) {
      *wr++ = (u8)(((rd[0]-'A') << 4) | ((rd[1]-'A') & 0xF));
      rd += 2;
      if ('\x20' == *(wr-1)) {
        wr--;
        break;
      }
    }
  }
  return (size_t)(wr-owr);
}

static ptrdiff_t do_parse_names(nb_dgm *d, size_t len, parse_frame *f)
{
  static nb_dgm_name name;
  char *orig = (char *)d + sizeof *d, /* byte after */
       *curr = orig;
  size_t l;
  /* attach and initialize */
  name.head = d;
  name.srcname = NULL;
  name.dstname = NULL;
  name.srcnamelen = 0;
  name.dstnamelen = 0;
  f->pass = &name;
  /* parse src name */
  l = memcspn(curr, len, "\0", 1);
  if (l >= len - 2) /* too long, no space for dest */
    return 0;
  name.srcname = curr;
  name.srcnamelen = l;
  curr += l, len -= l;
  /* skip \0 */
  l = memspn(curr, len, "\0", 1);
  curr += l, len -= l;
  /* parse dst name */
  l = memcspn(curr, len, "\0", 1);
  name.dstname = curr;
  name.dstnamelen = l;
  curr += l, len -= l;
  /* skip \0 */
  l = memspn(curr, len, "\0", 1);
  curr += l, len -= l;

  /* adjust strings */
  if (0 == name.srcnamelen || '\x20' != name.srcname[0] ||
      0 == name.dstnamelen || '\x20' != name.dstname[0])
    return 0;

  name.srcname++;
  name.srcnamelen--;
  name.srcnamelen = nb_decode_name(name.srcname, name.srcnamelen, name.srcname, name.srcnamelen);

  name.dstname++;
  name.dstnamelen--;
  name.dstnamelen = nb_decode_name(name.dstname, name.dstnamelen, name.dstname, name.dstnamelen);

  return curr - orig;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  nb_dgm *d = (nb_dgm *)buf;
  size_t consumed;
  /* sanity check packet */
  if (sizeof *d > len)
    return 0;
  /* convert endianness */
  d->id      = ntohs(d->id);
  d->len     = ntohs(d->len);
  d->srcport = ntohs(d->srcport);
  d->off     = ntohs(d->off);
  /* parse variable-length names off end */
  consumed = do_parse_names(d, len - sizeof *d, f);
  if (0 == consumed)
    return 0;
  consumed += sizeof *d;
  return consumed;
}

size_t dump(const parse_frame *f, int options, FILE *out)
{
  const nb_dgm_name *n = f->pass;
  const nb_dgm *d = n->head;
  int bytes = fprintf(out,
    "%s "
    "msgtype=%u snt=%u frag(f=%u more=%u) id=0x%04x "
    "src=%u.%u.%u.%u:%hu "
    "len=%hu off=%hu srcname=\"",
    Iface_NBDgm.shortname,
    d->msgtype, d->snt, d->f, d->m, d->id,
    d->srcip[0], d->srcip[1], d->srcip[2], d->srcip[3], d->srcport,
    d->len, d->off);
  bytes += dump_chars((char *)n->srcname, n->srcnamelen, out);
  bytes += fprintf(out, "\" dstname=\"");
  bytes += dump_chars((char *)n->dstname, n->dstnamelen, out);
  bytes += fprintf(out, "\"\n");
  /* report */
  {
    char srcbuf[64],
         ipbuf[64];
    const parse_frame *fi = f-2;
    const ipv4 *ip = fi->off;
    assert(PROT_IPv4 == fi->id);
    ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
    dump_chars_buf(srcbuf, sizeof srcbuf, (char *)n->srcname, n->srcnamelen);
    if ('\0' != srcbuf[0])
      rep_addr("4", ipbuf, "N", srcbuf, Iface_NBDgm.shortname, 1);
  }
  return (size_t)bytes;
}

static int init(void)
{
  printf("offsetof(nb_dgm, id) -> %u\n",
    (unsigned)offsetof(nb_dgm, id));
  assert(2 == offsetof(nb_dgm, id));
  assert(4 == offsetof(nb_dgm, srcip));
  assert(8 == offsetof(nb_dgm, srcport));
  printf("offsetof(nb_dgm, srcport) -> %u\n",
    (unsigned)offsetof(nb_dgm, srcport));
  assert(10 == offsetof(nb_dgm, len));
  printf("offsetof(nb_dgm, len) -> %u\n",
    (unsigned)offsetof(nb_dgm, len));
  assert(12 == offsetof(nb_dgm, off));
  printf("sizeof Dgm -> %u\n", (unsigned)sizeof Dgm);
  assert(14 == sizeof Dgm);
  return 1;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

