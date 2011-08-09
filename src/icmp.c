/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * ICMP
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "icmp.h"
#include "icmp-fingerprint.h"

static int    init(void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_ipv4(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IPv4, test_ipv4 }
};

/**
 * exported interface
 */
const prot_iface Iface_ICMP = {
  DINIT(id,           PROT_ICMP),
  DINIT(osi,          OSI_Net),
  DINIT(shortname,    "ICMP"),
  DINIT(propername,   "Internet Control Message Protocol"),
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
 * @ref #1 p.1
 */
static int test_ipv4(const char *buf, size_t len, const parse_status *st)
{
  const ipv4 *ip = (ipv4 *)st->frame[st->frames-1].off;
  return 1 == ip->protocol;
}

static const char * type_longname (u8 type);
static const char * code_str      (u8 type, u8 code);

static const char * const Nothing[] = {
  ""
};

static const char * const DestUnreachStr[] = {
  "Net Unreach",
  "Host Unreach",
  "Protocol Unreach",
  "Port Unreach",
  "Frag Needed",
  "Src Route"
};

static const char * const TimeExceedStr[] = {
  "TTL",
  "Frag"
};

static const char * const RedirectStr[] = {
  "Net",
  "Host",
  "ToS Net",
  "ToS Host"
};

static const icmp I;
const struct permsg PerMsg[Type_COUNT] = {
  { Type_EchoReply,       "reply",  "Echo Reply",     sizeof I.head + sizeof I.data.echo,     Nothing,        1 },
  { 1,                    "(1)",    "(1)",            0,                                      Nothing,        1 },
  { 2,                    "(2)",    "(2)",            0,                                      Nothing,        1 },
  { Type_DestUnreach,     "dstu",   "DestUnreach",    sizeof I.head + sizeof I.data.unreach,  DestUnreachStr, 5 },
  { Type_SourceQuench,    "srcq",   "SrcQuench",      sizeof I.head + sizeof I.data.unreach,  Nothing,        1 },
  { Type_Redirect,        "red",    "Redirect",       sizeof I.head + sizeof I.data.redirect, RedirectStr,    4 },
  { 6,                    "(6)",    "(6)",            0,                                      Nothing,        1 },
  { 7,                    "(7)",    "(7)",            0,                                      Nothing,        1 },
  { Type_Echo,            "echo",   "Echo",           sizeof I.head + sizeof I.data.echo,     Nothing,        1 },
  { 9,                    "(9)",    "(9)",            0,                                      Nothing,        1 },
  { 10,                   "(10)",   "(10)",           0,                                      Nothing,        1 },
  { Type_TimeExceed,      "tex",    "TimeExceed",     sizeof I.head + sizeof I.data.unreach,  TimeExceedStr,  2 },
  { Type_ParamProb,       "param",  "ParamProb",      sizeof I.head + sizeof I.data.param,    Nothing,        1 },
  { Type_Timestamp,       "ts",     "Timestamp",      sizeof I.head + sizeof I.data.timestamp,Nothing,        1 },
  { Type_TimestampReply,  "tsrep",  "TimestampReply", sizeof I.head + sizeof I.data.timestamp,Nothing,        1 },
  { Type_InfoReq,         "nforeq", "InfoReq",        sizeof I.head + sizeof I.data.info,     Nothing,        1 },
  { Type_InfoReply,       "nforep", "InfoReply",      sizeof I.head + sizeof I.data.info,     Nothing,        1 }
};

static void sanity_check(void)
{
  unsigned i;
  /* check that PerMsg .code == index */
  for (i = 0; i < sizeof PerMsg / sizeof PerMsg[0]; i++)
    assert(PerMsg[i].code == i);
}

static int init(void)
{
  sanity_check();
  return 1;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  icmp *i = (icmp *)buf;
  /* sanity check packet */
  if (sizeof I.head > len)                  /* not enough to even check code */
#if 0
    || i->head.code > 16                    /* code too high */
    || 0 == PerMsg[i->head.code].minbytes)  /* code invalid */
#endif
    return 0;
  /* convert endianness */
  i->head.chksum = ntohs(i->head.chksum);
  /* report */
  if (Type_Echo == i->head.type)
    report_echo_fingerprint(i, len, st);
  return len;
}

/**
 *
 */
static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const icmp *i = (icmp *)f->off;
  int bytes = fprintf(out,
      "%s type=%u(%s) code=0x%04x(%s) chksum=0x%04hx\n",
      Iface_ICMP.shortname, i->head.type, type_longname(i->head.type),
      (unsigned)i->head.code, code_str(i->head.type, i->head.code), i->head.chksum);
  if (Type_Echo == i->head.code || Type_EchoReply == i->head.code) {
    /* "ping" or "pong" */
    bytes += dump_chars((char *)i->data.echo.payload,
                        f->len - (i->data.echo.payload - (u8 *)i), stdout);
    fputc('\n', stdout);
    bytes++;
  }
  return (size_t)bytes;
}

static const char * type_longname(u8 type)
{
  const char *s = "?";
  if (type < sizeof PerMsg / sizeof PerMsg[0])
    s = PerMsg[type].longname;
  return s;
}

static const char *code_str(u8 type, u8 code)
{
  const char *c = "?";
  if (type < sizeof PerMsg / sizeof PerMsg[0] && code < PerMsg[type].codestrsize)
    c = PerMsg[type].codestr[code];
  return c;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[1024];
} TestCase[] = {
  { 48, "\x05\x01\xcd\xd4\x0a+o\x01""E\x00\x00(\xe2\xe8@\x00\x7f\x06\xcc\xff\x0a+aQ\xcf.\x11=\xe3\xcc\x01\xbb""b`\xa7\x84l8\xdc\xfaP\x10\xff\xff+M\x00\x00" },
  { 84, "\x05\x01?M\x0a+o\x01""E\x00\x00L\xe0j@\x00\x7f\x06^\x05\x0a+aQ\xcf\xea\x81\xd5\xdb\xe7\x00\x16\xe0i\x0d:\xdb\xe8\x14\xecP\x18\xfdWC\xf2\x00\x00\x20\xb6-x^\xd2\xac\xe2\xa0""ac(\\OEq\x8e\x90\xd1/\xbb\xe4\xe6\xf2\xc6~j\xecg\xf0q(\xc2\x85'\xdc" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_ICMP, T->len, T->txt, NULL };
    printf("#%2u: ", i);
    dump_chars(T->txt, T->len, stdout);
    fputc('\n', stdout);
    fflush(stdout);
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




