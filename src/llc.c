/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * LLC
 */

#include <assert.h>
#include <stdio.h>
#include <string.h> /* memcpy */
#include <stdlib.h> /* offsetof() */
#include <arpa/inet.h>
#include <pcap.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "logical.h"
#include "ieee802_3.h"
#include "llc.h"

static int    init(void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_ieee802_3(const char *, size_t, const parse_status *);
static int test_ATM_RFC1483(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IEEE802_3, test_ieee802_3   },
  { PROT_LOGICAL,   test_ATM_RFC1483 }
};

/**
 * exported interface
 */
const prot_iface Iface_LLC = {
  DINIT(id,           PROT_LLC),
  DINIT(osi,          OSI_Link),
  DINIT(shortname,    "LLC"),
  DINIT(propername,   "Logical Link Control"),
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

static const ieee802_3_mac_addr LLC_MAC = {
  { 0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC }
};


static int test_ieee802_3(const char *buf, size_t len, const parse_status *st)
{
	const ethernet2_frame *f = (ethernet2_frame *)st->frame[st->frames-1].off;
	return IEEE802_3_IS_LEN(f->lentype)
      || 0 == ieee802_3_mac_addr_cmp(&LLC_MAC, &f->dst);
}

static int test_ATM_RFC1483(const char *buf, size_t len, const parse_status *st)
{
  const logical_frame *f = st->frame[st->frames-1].off;
	return len >= sizeof *f
      && len >= sizeof(llc)
      && DLT_ATM_RFC1483 == f->type;
}

static size_t ctrl_bytes(const llc *);
static size_t do_parse(llc *, size_t);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  llc *l = (llc *)buf;
  size_t bytes;
  /* sanity check packet */
  if (len < 3)
    return 0;
  bytes = do_parse(l, len);
  if (bytes > len)
    bytes = 0;
  return bytes;
}

size_t dump(const parse_frame *f, int options, FILE *out)
{
  const llc *l = (llc *)f->off;
  const llc_pid *p = llc_getpid(l);
  int bytes = fprintf(out,
    "%s dsap(ig=%u addr=0x%02x) ssap(cr=%u addr=0x%02x) cmd=0x%02x",
    Iface_LLC.shortname,
    l->dsap.ig, l->dsap.all,
    l->ssap.cr, l->ssap.all,
    l->ctrl.cmd);
  if (p) {
    bytes += fprintf(out, " org=0x%02x%02x%02x pid=0x%04hx",
      (u8)p->org[0], (u8)p->org[1], (u8)p->org[2], p->pid);
  }
  fputc('\n', out);
  bytes++;
  return (size_t)bytes;
}

static size_t ctrl_bytes(const llc *l)
{
  size_t bytes = 4;
  if (3 == l->ctrl.u.eleven)
    bytes = 3;
  return bytes;
}

static size_t do_parse(llc *l, size_t len)
{
  size_t bytes = ctrl_bytes(l);
  if (LLC_SNAP == l->dsap.all && LLC_SNAP == l->ssap.all) {
    llc_pid *p = (llc_pid *)((u8 *)l + bytes);
    p->pid = ntohs(p->pid);
    bytes += sizeof *p;
  }
  return bytes;
}

/**
 * return a pointer to the 'pid' section of an llc message, should one
 * exist; NULL otherwise. meant to hid ethe gory details from other
 * modules that wish to examine the pid field.
 */
llc_pid * llc_getpid(const llc *l)
{
  llc_pid *p = NULL;
  if (LLC_SNAP == l->dsap.all && LLC_SNAP == l->ssap.all)
    p = (llc_pid *)((char *)l + ctrl_bytes(l));
  return p;
}

/**
 * verify contents of packet structure
 */
static void sanity_check(void)
{
  const llc L;
  assert(0 == offsetof(llc, dsap));
  assert(1 == sizeof L.dsap);
  assert(1 == offsetof(llc, ssap));
  assert(1 == sizeof L.ssap);
}

static int init(void)
{
  sanity_check();
  /* initialize data */
  return 1;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[8];
} TestCase[] = {
  { 8, "\xaa\xaa\x03\x00\x00\x0c\x01\x0b" },
  { 3, "\xf0\xf0\x03" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_LLC, T->len, T->txt, NULL };
    size_t bytes;
    printf("#%2u: ", i);
    dump_chars(T->txt, T->len, stdout);
    fputc('\n', stdout);
    bytes = parse(T->txt, T->len, &pf, NULL);
    dump(&pf, 0, stdout);
    fputc('\n', stdout);
    assert(bytes == T->len);
    T++;
  }
}

int main(void)
{
  test();
  return 0;
}
#endif




