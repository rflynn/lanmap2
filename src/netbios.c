/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * NetBIOS
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "llc.h"
#include "ipx.h"
#include "netbios.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_llc(const char *, size_t, const parse_status *);
static int test_ipx(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_LLC, test_llc },
  { PROT_IPX, test_ipx }
};

/**
 * exported interface
 */
const prot_iface Iface_NetBIOS = {
  DINIT(id,           PROT_NetBIOS),
  DINIT(osi,          OSI_Sess),
  DINIT(shortname,    "NetBIOS"),
  DINIT(propername,   "Network Basic Input/Output System"),
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

static int test_llc(const char *buf, size_t len, const parse_status *st)
{
  const llc *l = st->frame[st->frames-1].off;
  return NETBIOS_LLC == l->dsap.all
      && NETBIOS_LLC == l->ssap.all;
}

static int test_ipx(const char *buf, size_t len, const parse_status *st)
{
  const ipx *i = st->frame[st->frames-1].off;
  return IPX_Socket_NetBIOS == ntohs(i->dst.socket)
      && IPX_Socket_NetBIOS == ntohs(i->src.socket);
}

static size_t parse_dgram(const netbios *, char *, size_t, const parse_status *);
static size_t parse_qry  (const netbios *, char *, size_t, const parse_status *);

static size_t dump_dgram (const netbios *, const parse_frame *, FILE *);
static size_t dump_qry   (const netbios *, const parse_frame *, FILE *);

static const struct bycmd {
  enum Cmd cmd;
  const char *shortname,
             *longname;
  size_t minbytes;
  size_t (*parse)(const netbios *, char *, size_t, const parse_status *);
  size_t (*dump)(const netbios *, const parse_frame *, FILE *);
} PerCmd[] = {
  { 0,            "(0)",    "(0)",      0,                NULL,         NULL        },
  { 1,            "(1)",    "(1)",      0,                NULL,         NULL        },
  { 2,            "(2)",    "(2)",      0,                NULL,         NULL        },
  { 3,            "(3)",    "(3)",      0,                NULL,         NULL        },
  { 4,            "(4)",    "(4)",      0,                NULL,         NULL        },
  { 5,            "(5)",    "(5)",      0,                NULL,         NULL        },
  { 6,            "(6)",    "(6)",      0,                NULL,         NULL        },
  { 7,            "(7)",    "(7)",      0,                NULL,         NULL        },
  { Cmd_Datagram, "dgram",  "Datagram", sizeof(nb_dgram), parse_dgram,  dump_dgram  },
  { 9,            "(9)",    "(9)",      0,                NULL,         NULL        },
  { Cmd_Query,    "qry",    "Query",    sizeof(nb_qry),   parse_qry,    dump_qry    }
};

static const struct bycmd *bycmd(u8 cmd)
{
  const struct bycmd *b = NULL;
  if (cmd < sizeof PerCmd / sizeof PerCmd[0])
    b = PerCmd + cmd;
  return b;
}

static const struct bytype {
  enum Type type;
  const char *shortname,
             *longname;
} PerType[] = {
  { Type_Workstation, "workstation",  "Workstation/Repeater"  },
  { Type_LocalMaster, "local master", "Local Master"          }
};

static const struct bytype *bytype(u8 type)
{
  const struct bytype *t = NULL;
  unsigned i;
  for (i = 0; i < sizeof PerType / sizeof PerType[0]; i++) {
    if (PerType[i].type == type) {
      t = PerType + i;
      break;
    }
  }
  return t;
}

static const char * type2short(u8 type)
{
  const char *s = "?";
  const struct bytype *t = bytype(type);
  if (t)
    s = t->shortname;
  return s;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  netbios *n = (netbios *)buf;
  const struct bycmd *c;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *n > len)
    return 0;
  /* convert endianness */
  n->len = ltohs(n->len);
  c = bycmd(n->cmd);
  len -= sizeof *n;
  if (c) {
    if (len < c->minbytes)
      return 0;
    if (NULL == c->parse)
      return 0;
    bytes = (*c->parse)(n, buf + sizeof *n, len, st);
    assert(bytes <= len);
  } else {
    bytes = len;
  }
  return sizeof *n + bytes;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const netbios *n = f->off;
  const struct bycmd *c = bycmd(n->cmd);
  int bytes;
  bytes = fprintf(out, "%s len=%hu delim=0x%02x%02x cmd=0x%02x\n",
    Iface_NetBIOS.shortname, n->len, (u8)n->delim[0], (u8)n->delim[1], n->cmd);
  if (c->dump)
    bytes += (*c->dump)(n, f, out);
  return (size_t)bytes;
}

static size_t nametype_format(char *buf, size_t len, const nametype *t)
{
  size_t l;
  assert(len > sizeof t->name * 4);
  l = memcspn((char *)t->name, sizeof t->name, " ", 1);
  return dump_chars_buf(buf, len, (char *)t->name, l);
}

static size_t parse_dgram(const netbios *n, char *buf, size_t len, const parse_status *st)
{
  nb_dgram *d = (nb_dgram *)buf;
  return sizeof *d;
}

static size_t dump_dgram(const netbios *n, const parse_frame *f, FILE *out)
{
  char rcvbuf[64+1],
       sndbuf[64+1];
  const nb_dgram *d = (nb_dgram *)((char *)f->off + sizeof(netbios));
  int used;
  nametype_format(rcvbuf, sizeof rcvbuf, &d->rcv);
  nametype_format(sndbuf, sizeof sndbuf, &d->snd);
  used = fprintf(out, " DGRAM "
    "rcv(\"%s\" type=0x%02x(%s)) "
    "snd(\"%s\" type=0x%02x(%s))\n",
    rcvbuf, d->rcv.type, type2short(d->rcv.type),
    sndbuf, d->snd.type, type2short(d->snd.type));
  return (size_t)used;
}

static size_t parse_qry(const netbios *n, char *buf, size_t len, const parse_status *st)
{
  nb_qry *q = (nb_qry *)buf;
  q->respcorollate = ltohs(q->respcorollate);
  return sizeof *q;
}

static size_t dump_qry(const netbios *n, const parse_frame *f, FILE *out)
{
  char whobuf[64+1];
  const nb_qry *q = (nb_qry *)((char *)f->off + sizeof(netbios));
  int used;
  nametype_format(whobuf, sizeof whobuf, &q->who);
  used = fprintf(out, " QUERY localsess=0x%02x callernametype=0x%02x respcor=0x%02x who(\"%s\" type=0x%02x(%s)) name=\"%.*s\"\n", 
    q->localsess, q->callernametype, q->respcorollate, whobuf, q->who.type, type2short(q->who.type),
    sizeof q->name, q->name);
  return (size_t)used;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[256];
} TestCase[] = {
  { 44, "\x2c\x00\xff\xef\x0a\x00\x00\x00\x00\x00\x4d\x5e\x57\x4f\x52\x4b\x47\x52\x4f\x55\x50\x20\x20\x20\x20\x20\x20\x1d\x58\x43\x2d\x33\x37\x37\x45\x32\x43\x20\x20\x20\x20\x20\x20\x20" },
  { 44, "\x2c\x00\xff\xef\x0a\x00\x00\x00\x00\x00\x7f\x1e\x57\x4f\x52\x4b\x47\x52\x4f\x55\x50\x20\x20\x20\x20\x20\x20\x1d\x58\x43\x2d\x33\x38\x39\x38\x44\x42\x20\x20\x20\x20\x20\x20\x20" },
  { 44, "\x2c\x00\xff\xef\x08\x00\x00\x00\x00\x00\x00\x00\x57\x4f\x52\x4b\x47\x52\x4f\x55\x50\x20\x20\x20\x20\x20\x20\x1d\x58\x43\x2d\x33\x38\x39\x38\x44\x42\x20\x20\x20\x20\x20\x20\x00" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_NetBIOS, T->len, T->txt, NULL };
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



