/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * DHCPv6
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h> /* offsetof() */
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "report.h"
#include "ieee802_3.h"
#include "ipv4.h"
#include "udp.h"
#include "dhcpv6.h"

static int    init(void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp_port(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp_port }
};

/**
 * exported interface
 */
const prot_iface Iface_DHCPv6 = {
  DINIT(id,           PROT_DHCPv6),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "DHCPv6"),
  DINIT(propername,   "Dynamic Host Configuration Protocol for IPv6"),
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

static int test_udp_port(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = st->frame[st->frames-1].off;
  printf("%s srcport=%hu dstport=%hu\n",
    __func__, u->srcport, u->dstport);
  return (
    /* server -> client */
    (DHCPv6_UDP_PORT_SERVER == u->srcport &&
     DHCPv6_UDP_PORT_CLIENT == u->dstport) ||
    /* client -> server */
    (DHCPv6_UDP_PORT_CLIENT == u->srcport &&
     DHCPv6_UDP_PORT_SERVER == u->dstport));
}

static size_t do_dump_str(const char *buf, size_t len, FILE *out)
{
  dump_chars(buf, len, out);
  return len;
}

static size_t do_dump_ipv6(const char *buf, size_t len, FILE *out)
{
  char ipbuf[48];
  size_t olen = len,
         bytes = 0;
  while (len >= 4) {
    ipv6_addr_format(ipbuf, sizeof ipbuf, buf);
    bytes += fprintf(out, "%s%s", len == olen ? "" : " ", ipbuf);
    buf += sizeof(ipv6_addr), len -= sizeof(ipv6_addr);
  }
  return bytes;
}

static const struct bytype {
  enum MsgType type;
  const char  shortname[4],
             *longname;
} PerType[MsgType_COUNT] = {
  { 0,              "(0)",      "(0?!)"               },
  { SOLICIT,        "Sol",      "Solicit"             },
  { ADVERTISE,      "Adv",      "Advertise"           },
  { REQUEST,        "Req",      "Request"             },
  { CONFIRM,        "Cnf",      "Confirm"             },
  { RENEW,          "Ren",      "Renew"               },
  { REBIND,         "Reb",      "Rebind"              },
  { REPLY,          "Rep",      "Reply"               },
  { RELEASE,        "Rel",      "Release"             },
  { DECLINE,        "Dec",      "Decline"             },
  { RECONFIGURE,    "Rec",      "Reconfigure"         },
  { INFO_REQUEST,   "Inf",      "Information Request" },
  { RELAY_FORW,     "RFW",      "Relay ForW"          },
  { RELAY_REPL,     "RRP",      "Replay Reply"        }
};

static const struct bytype * bytype(u8 type)
{
  const struct bytype *t = NULL;
  if (type < sizeof PerType / sizeof PerType[0])
    t = PerType + type;
  return t;
}

static const struct byopt {
  enum OPTION code;
  const char *name;
  size_t (*dump)(const char *, size_t, FILE *);
} PerOpt[OPTION_COUNT] = {
  { 0,                    "(0)",          do_dump_str },
  { OPTION_CLIENTID,      "Client ID",    do_dump_str },
  { OPTION_SERVERID,      "Server ID",    do_dump_str },
  { OPTION_IA_NA,         "IA NA",        do_dump_str },
  { OPTION_IA_TA,         "IA TA",        do_dump_str },
  { OPTION_IAADDR,        "IA Addr",      do_dump_str },
  { OPTION_ORO,           "Opt Req Opt",  do_dump_str },
  { OPTION_PREFERENCE,    "Preference",   do_dump_str },
  { OPTION_ELAPSED_TIME,  "Elapsed Time", do_dump_str },
  { OPTION_RELAY_MSG,     "Relay Msg",    do_dump_str },
  { 10,                   "(10)",         do_dump_str },
  { OPTION_AUTH,          "Auth",         do_dump_str },
  { OPTION_UNICAST,       "Unicast",      do_dump_str },
  { OPTION_STATUS_CODE,   "Status Code",  do_dump_str },
  { OPTION_RAPID_COMMIT,  "Rapid Commit", do_dump_str },
  { OPTION_USER_CLASS,    "User Class",   do_dump_str },
  { OPTION_VENDOR_CLASS,  "Vendor Class", do_dump_str },
  { OPTION_VENDOR_OPTS,   "Vendor Opts",  do_dump_str },
  { OPTION_INTERFACE_ID,  "Iface ID",     do_dump_str },
  { OPTION_RECONF_MSG,    "Reconf Msg",   do_dump_str },
  { OPTION_RECONF_ACCEPT, "Reconf Accept",do_dump_str },
};

static const struct byopt *byopt(u16 code)
{
  const struct byopt *b = NULL;
  if (code < sizeof PerOpt / sizeof PerOpt[0])
    b = PerOpt + code;
  return b;
}

static size_t opt_dump(enum OPTION code, const char *buf, size_t len, FILE *out)
{
  size_t bytes = 0;
  const struct byopt *b = byopt(code);
  if (b)
    bytes = (*b->dump)(buf, len, out);
  return bytes;
}

static size_t do_parse_opts(char *buf, size_t len, parse_frame *f, const parse_status *st);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  dhcpv6 *d = (dhcpv6 *)buf;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *d > len)
    return 0;
  bytes = do_parse_opts(buf + sizeof *d, len - sizeof *d, f, st);
  if (bytes > 0)
    bytes += sizeof *d;
  /* NOTE: sizeof *d + bytes should == len */
  return bytes;
}

static void do_parse_opt(const dhcpv6_opt *, dhcpv6_fingerprint *, const parse_status *);

static size_t do_parse_opts(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  dhcpv6_fingerprint p; /* unused atm */
  const char *obuf = buf,
             *end  = buf + len;
  dhcpv6_opt *o;

  printf("dhcpv6 opts len=%u\n", (unsigned)len);
  dump_chars(buf, (unsigned)len, stdout);
  fputc('\n', stdout);

  while (buf <= end - sizeof *o) {
    o = (dhcpv6_opt *)buf; 
    const struct byopt *bo;
    o->code = ntohs(o->code);
    o->len = ntohs(o->len);
    if (o->len > len) /* bogus data */
      break;
    bo = byopt(o->code);
    printf(" #%2u %-15s len=%-3u ",
      o->code, bo ? bo->name : "?", o->len);
    (void)opt_dump(o->code, buf + sizeof *o, o->len, stdout);
    fputc('\n', stdout);
    do_parse_opt(o, &p, st);
    buf += sizeof *o + o->len;
    len -= sizeof *o + o->len;
  }
  return (size_t)(buf - obuf);
}

/**
 * handle any processing/reporting for a bootp opt
 */
static void do_parse_opt(
  const dhcpv6_opt *o,
  dhcpv6_fingerprint *p,
  const parse_status *st)
{
}

size_t dump(const parse_frame *f, int options, FILE *out)
{
  const dhcpv6 *d = f->off;
  const struct bytype *t = bytype(d->msgtype);
  int bytes = fprintf(out,
    "%s msgtype=0x%2x(%s) "
    "transid=0x%02x%02x%02x\n",
    Iface_DHCPv6.shortname, d->msgtype, t ? t->longname : "?",
    (u8)d->transid[0], (u8)d->transid[1], (u8)d->transid[2]);
  return (size_t)bytes;
}

/**
 * check our dictionaries to ensure no items are missing
 */
static void check_dicts(void)
{
  unsigned i;

  printf("%s checking PerType...", __FILE__);
  fflush(stdout);
  for (i = 0; i < sizeof PerType / sizeof PerType[0]; i++) {
    printf(" 0x%02x", i);
    assert(PerType[i].type == i);
  }
  fputc('\n', stdout);

  printf("%s checking PerOpt...", __FILE__);
  fflush(stdout);
  for (i = 0; i < sizeof PerOpt / sizeof PerOpt[0]; i++) {
    printf(" 0x%02x", i);
    assert(PerOpt[i].code == i);
  }
  fputc('\n', stdout);

}

static void sanity_check(void)
{
  printf("%s:sanity_check... ", __FILE__);
  fflush(stdout);
  assert(4 == sizeof(dhcpv6));
  assert(4 == sizeof(dhcpv6_opt));
  printf("ok.\n");
}

static int init(void)
{
  sanity_check();
  check_dicts();
  return 1;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[256];
} TestCase[] = {
  { 76, "\x01\xe1\xc3\x87\x00\x08\x00\x02\x00\x00\x00\x01\x00\x0a\x00\x03\x00\x01\x00\x1f)\x20\xcb""0\x00\x03\x00(\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x07\xd0\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\xd0\x00\x00\x0b\xb8\x00\x06\x00\x04\x00\x0d\x00\x07" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_DHCPv6, T->len, T->txt, NULL };
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

