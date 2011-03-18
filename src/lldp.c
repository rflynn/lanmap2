/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2011 Ryan Flynn
 * All rights reserved.
 */
/*
 * LLDP
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "ieee802_3.h"
#include "ipv4.h"
#include "lldp.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_eth(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IEEE802_3, test_eth }
};

/**
 * exported interface
 */
const prot_iface Iface_LLDP = {
  DINIT(id,           PROT_LLDP),
  DINIT(osi,          OSI_Link),
  DINIT(shortname,    "LLDP"),
  DINIT(propername,   "Link Layer Discovery Protocol"),
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

static int test_eth(const char *buf, size_t len, const parse_status *st)
{
  const ethernet2_frame *e = (ethernet2_frame *)st->frame[st->frames-1].off;
  return LLDP_ETH_TYPE == e->lentype;
      //&& 0 == memcmp(LLDP_ETH_DST, e->src.o, sizeof e->src.o);
}

static size_t do_parse(lldp *, size_t, const parse_status *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  lldp *l = (lldp *)buf;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *l > len)
    return 0;
  bytes = do_parse(l, len, st);
  return bytes;
}

static size_t do_dump(const lldp *, size_t, FILE *);
static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const lldp *l = (lldp *)f->off;
  int bytes = fprintf(out,
    "%s\n", Iface_LLDP.shortname);
  bytes += do_dump(l, f->len, out);
  return (size_t)bytes;
}

static void rep_SysDescr(const char *, size_t, const parse_status *);
static void rep_SysName (const char *, size_t, const parse_status *);

static const struct type_struct {
  enum Type type;
  const char *descr;
  size_t (*parse)(const char *, size_t, const parse_status *);
  void     (*rep)(const char *, size_t, const parse_status *);
  size_t  (*dump)(const lldp *, size_t, FILE *);
} ByType[] = {
  { Type_EndOfMsg,  "EndofMsg",   NULL,          NULL,          NULL         },
  { Type_ChassisId, "ChassisId",  NULL,          NULL,          NULL         },
  { Type_PortId,    "PortId",     NULL,          NULL,          NULL         },
  { Type_TTL,       "TTL",        NULL,          NULL,          NULL         },
  { Type_PortDescr, "PortDescr",  NULL,          NULL,          NULL         },
  { Type_SysName,   "SysName",    NULL,          rep_SysName,   NULL         },
  { Type_SysDescr,  "SysDescr",   NULL,          rep_SysDescr,  NULL         },
  { Type_SysCapab,  "SysCapab",   NULL,          NULL,          NULL         },
  { Type_MgmtAddr,  "MgmtAddr",   NULL,          NULL,          NULL         }
};

static size_t do_parse(lldp *l, size_t len, const parse_status *st)
{
  const u8 *obuf = (u8 *)l;
  while (len >= sizeof *l) {
    printf("%s:%u sizeof *l=%zu len=%zu l->len=%hu\n",__func__, __LINE__, sizeof *l, len, l->len);
    u16 *u = (u16 *)l;
    *u = ntohs(*u);
    if (2U + l->len > len)
      break;
    if (Type_EndOfMsg == l->type) {
      l = (lldp *)((u8 *)l + 2);
      break;
    }
    if (l->type < sizeof ByType / sizeof ByType[0]) {
      if (ByType[l->type].parse)
        (*ByType[l->type].parse)((char *)l->val, l->len, st);
      if (ByType[l->type].rep)
        (*ByType[l->type].rep)((char *)l->val, l->len, st);
    }
    len -= 2U + l->len;
    l = (lldp *)(l->val + l->len);
  }
  return (size_t)((u8 *)l - obuf);
}

static void rep_SysDescr(const char *buf, size_t len, const parse_status *st)
{
  if (st->frames >= 2 && PROT_IEEE802_3 == st->frame[st->frames-1].id) {
    char macbuf[32];
    const ethernet2_frame *e = st->frame[st->frames-1].off;
    (void)ieee802_3_addr_format(macbuf, sizeof macbuf, &e->src);
#ifndef TEST
    rep_hint("M", macbuf, "LLDP.SysDescr", buf, (int)len);
#endif
  }
}

static void rep_SysName(const char *buf, size_t len, const parse_status *st)
{
  if (st->frames >= 2 && PROT_IEEE802_3 == st->frame[st->frames-1].id) {
    char macbuf[32];
    const ethernet2_frame *e = st->frame[st->frames-1].off;
    (void)ieee802_3_addr_format(macbuf, sizeof macbuf, &e->src);
#ifndef TEST
    rep_hint("M", macbuf, "LLDP.SysName", buf, (int)len);
#endif
  }
}

static size_t do_dump(const lldp *l, size_t len, FILE *out)
{
  size_t bytes = 0;
  while (len >= sizeof *l && 2U + l->len <= len) {
    if (l->type < sizeof ByType / sizeof ByType[0]) {
      int used = fprintf(out, "  %-9s ", ByType[l->type].descr);
      if (used > 0)
        bytes = bytes + (size_t)used;
      if (ByType[l->type].dump) {
        bytes += (*ByType[l->type].dump)(l, l->len, out);
      } else {
        bytes += dump_chars((char *)l->val, l->len, out);
      }
    } else {
      int used = fprintf(out, "  %-9u ", l->type);
      if (used > 0)
        bytes = bytes + (size_t)used;
      bytes += dump_chars((char *)l->val, l->len, out);
    }
    fputc('\n', out);
    bytes++;
    if (Type_EndOfMsg == l->type)
      break;
    len -= 2U + l->len;
    l = (lldp *)(l->val + l->len);
  }
  return bytes;
}

#ifdef TEST

#include <assert.h>

static struct {
  size_t len;
  char txt[256];
} TestCase[] = {
  { 0, ""                    },
  { 254,
"\x00\x2d\x08\x00\x00\x76\x00\x00"
"\x00\x06\x00\x07\x00\x00\x00\x01"
"\x0a\x2c\x16\xb5\x00\x00\x00\x00"
"\x09\x2b\x00\x00\x00\x00\x02\x03"
"\x03\x00\x00\x00\x00\x00\x00\x01"
"\x54\x45\x53\x54\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x0a\x30\x34"
"\x2e\x30\x32\x2d\x31\x39\x00\x00"
"\x00\x00\x00\x00\x00\x00\x45\x6e"
"\x67\x69\x6e\x65\x65\x72\x69\x6e"
"\x67\x20\x4c\x61\x62\x2c\x20\x54"
"\x45\x53\x54\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00" },
  { 166, "\x01\x80\xc2\x00\x00\x0e\x00\x1d\xb3\xc5\x94\xb3\x88\xcc\x02\x07\x04\x00\x1d\xb3\xc5\x94\xa0\x04\x03\x07""13\x06\x02\x00x\x08\x02""13\x0a\x1dHP 2510 asu rem spichka urtop\x0cYProCurve J9019B Switch 2510B-24, revision Q.11.26, ROM Q.10.02 (/sw/code/build/harp(bh2))\x0e\x04\x00\x04\x00\x04\x10\x0c\x05\x01\x0a\x0a\x01o\x02\x00\x00\x00\x00\x00\x00\x00" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++, T++) {
    parse_frame f = { PROT_IEEE802_3, T->len, (void*)T->txt, NULL };
    printf("#%2u: ", i);
    dump_chars(T->txt, T->len, stdout);
    fflush(stdout);
    {
      size_t bytes = parse(f.off, f.len, &f, NULL);
      printf(" len=%u parsed=%u\n", (unsigned)f.len, (unsigned)bytes);
      dump(&f, 0, stdout);
      assert(bytes <= f.len);
    }
  }
}

int main(void)
{
  test();
  return 0;
}
#endif

