/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * STP
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "ieee802_3.h"
#include "llc.h"
#include "stp.h"

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_llc_pid (const char *, size_t, const parse_status *);
static int test_llc_dsap(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_LLC, test_llc_pid  },
  { PROT_LLC, test_llc_dsap }
};

/**
 * exported interface
 */
const prot_iface Iface_STP = {
  DINIT(id,           PROT_STP),
  DINIT(osi,          OSI_Link),
  DINIT(shortname,    "STP"),
  DINIT(propername,   "Spanning Tree Protocol"),
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

static int test_llc_pid(const char *buf, size_t len, const parse_status *st)
{
  const llc *l = st->frame[st->frames-1].off;
  const llc_pid *p = llc_getpid(l);
  return p && STP_LLC_PID == p->pid;
}

static int test_llc_dsap(const char *buf, size_t len, const parse_status *st)
{
  const llc *l = st->frame[st->frames-1].off;
  return LLC_DSAP_ST_BDPU == l->dsap.addr;
}

static void do_rep(const stp *s, const parse_status *st);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  stp *s = (stp *)buf;
  /* sanity check packet */
  if (sizeof *s > len)
    return 0;
  /* convert endianness */
  s->protocol       = ntohs(s->protocol);
  s->root.id        = ntohs(s->root.id);
  s->root.path_cost = ntohl(s->root.path_cost);
  s->bridge.id      = ntohs(s->bridge.id);
  /* FIXME: i am confused about the byte order of these fields */
  s->port           = ltohs(s->port);
  s->msg_age        = ltohs(s->msg_age);
  s->msg_maxage     = ltohs(s->msg_maxage);
  s->forward        = ltohs(s->forward);
  do_rep(s, st);
  return sizeof *s;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const stp *s = (stp *)f->off;
  int bytes = fprintf(out,
    "%s "
    "prot=0x%hx ver=%u bpdu-type=0x%x topo-change(%u ack=%u) "
    "root(%02x:%02x:%02x:%02x:%02x:%02x id=0x%hx cost=%lu) "
    "bridge(%02x:%02x:%02x:%02x:%02x:%02x id=0x%hx) "
    "port=%hu msg(age=%hu maxage=%hu) hello=%hu fwd=%u\n",
    Iface_STP.shortname,
    s->protocol, s->version, s->bpdu_type, s->topo_change, s->topo_change_ack,
    s->root.mac.o[0], s->root.mac.o[1], s->root.mac.o[2], s->root.mac.o[3], s->root.mac.o[4], s->root.mac.o[5],
    s->root.id, (unsigned long)s->root.path_cost,
    s->bridge.mac.o[0], s->bridge.mac.o[1], s->bridge.mac.o[2], s->bridge.mac.o[3], s->bridge.mac.o[4], s->bridge.mac.o[5],
    s->bridge.id,
    s->port, s->msg_age, s->msg_maxage, s->hello, s->forward);
  return (size_t)bytes;
}

static void do_rep_bridge(const ieee802_3_mac_addr *mac)
{
  char macbuf[32];
  (void)ieee802_3_addr_format(macbuf, sizeof macbuf, mac);
  rep_hint("M", macbuf, "STP.Bridge", macbuf, -1);
}

static void do_rep(const stp *s, const parse_status *st)
{
  do_rep_bridge(&s->root.mac);
  do_rep_bridge(&s->bridge.mac);
} 

static int init(void)
{
  assert(35 == sizeof(stp));
  return 1;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

