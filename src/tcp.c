/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * TCP version 4
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "util.h"
#include "prot.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp-fingerprint.h"

int    tcp_init(void);
size_t tcp_parse(char *, size_t, parse_frame *, const parse_status *);
size_t tcp_dump(const parse_frame *, int options, FILE *);

static int test_ipv4(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IPv4, test_ipv4 }
};

/**
 * exported interface
 */
const prot_iface Iface_TCP = {
  DINIT(id,           PROT_TCP),
  DINIT(osi,          OSI_Trans),
  DINIT(shortname,    "TCP"),
  DINIT(propername,   "Transmission Control Protocol"),
  DINIT(init,         tcp_init),
  DINIT(unload,       NULL),
  DINIT(parse,        tcp_parse),
  DINIT(dump,         tcp_dump),
  DINIT(addr_type,    NULL),
  DINIT(addr_from,    NULL),
  DINIT(addr_to,      NULL),
  DINIT(addr_format,  NULL),
  DINIT(addr_local,   NULL),
  DINIT(parents,      sizeof Test / sizeof Test[0]),
  DINIT(parent,       Test)
};

static int test_ipv4(const char *buf, size_t len, const parse_status *st)
{
  const ipv4 *ip = st->frame[st->frames-1].off;
  return 0x6 == ip->protocol;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
size_t tcp_parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  tcp *t = (tcp *)buf;
  size_t bytes = t->off * 4;
  /* sanity check packet */
  /* convert endianness */
  t->srcport = ntohs(t->srcport);
  t->dstport = ntohs(t->dstport);
  t->seqno   = ntohl(t->seqno);
  t->ackno   = ntohl(t->ackno);
  t->window  = ntohs(t->window);
  t->chksum  = ntohs(t->chksum);
  t->urgptr  = ntohs(t->urgptr);
  /* report */
#ifndef NOREP
  tcp_rep(st, t, bytes);
#endif
  return bytes;
}

static ptrdiff_t dump_opts(const tcp *, const parse_frame *, int opt, FILE *out);
size_t tcp_dump(const parse_frame *f, int opt, FILE *out)
{
  const tcp *t = (tcp *)f->off;
  int bytes = fprintf(out,
    "%s "
    "srcport=%hu dstport=%hu seqno=%lu ackno=%lu "
    "fin=%u syn=%u rst=%u psh=%u ack=%u urg=%u ecn=%u cwr=%u "
    "res=0x%hx off=%u win=%hu chksum=0x%04hx urgptr=%hu\n",
    Iface_TCP.shortname,
    t->srcport, t->dstport, (unsigned long)t->seqno, (unsigned long)t->ackno,
    t->fin, t->syn, t->rst, t->psh, t->ack, t->urg, t->ecn, t->cwr,
    t->reserved, t->off, t->window, t->chksum, t->urgptr);
  bytes += dump_opts(t, f, opt, out);
  return (size_t)bytes;
}

static const struct {
  enum TCP_Opt opt;
  const char *shortname,
             *longname;
  size_t (*dump)(const void *, size_t);
  size_t (*tostr)(char *, size_t, void *, size_t);
} PerOpt[] = {
  { TCP_Opt_End,        "EOL",        "End of Option List",    NULL, NULL },
  { TCP_Opt_NOP,        "NOP",        "No-Operation",          NULL, NULL },
  { TCP_Opt_MSS,        "MSS",        "Maximum Segment Size",  NULL, NULL },
  { TCP_Opt_WSOPT,      "WSS",        "Window Scaling",        NULL, NULL },
  { TCP_Opt_SACKPerm,   "SACKP",      "",                      NULL, NULL },
  { TCP_Opt_SACK,       "SACK",       "Selective Ack",         NULL, NULL },
  { TCP_Opt_Echo,       "Echo",       "",                      NULL, NULL },
  { TCP_Opt_EchoReply,  "EchoRep",    "",                      NULL, NULL },
  { TCP_Opt_TSOPT,      "TS",         "Timestamp",             NULL, NULL },
  { TCP_Opt_POCP,       "POCP",       "",                      NULL, NULL },
  { TCP_Opt_POSP,       "POSP",       "",                      NULL, NULL },
  { TCP_Opt_CC,         "CC",         "",                      NULL, NULL },
  { TCP_Opt_CCNEW,      "CCNEW",      "",                      NULL, NULL },
  { TCP_Opt_CCECHO,     "CCECHO",     "",                      NULL, NULL },
  { TCP_Opt_AltChkReq,  "AltChkReq",  "",                      NULL, NULL },
  { TCP_Opt_AltChkData, "AltChkData", "",                      NULL, NULL },
  { TCP_Opt_Skeeter,    "Skeeter",    "",                      NULL, NULL },
  { TCP_Opt_Bubba,      "Bubba",      "",                      NULL, NULL },
  { TCP_Opt_TrailChksum,"TrailChk",   "Trailing Checksum",     NULL, NULL },
  { TCP_Opt_MD5Sig,     "MD5",        "",                      NULL, NULL },
  { TCP_Opt_SCPS,       "SCPS",       "SCPS",                  NULL, NULL },
  { TCP_Opt_SNA,        "SNA",        "Selective Negative Ack",NULL, NULL },
  { TCP_Opt_RecBound,   "RecBnd",     "",                      NULL, NULL },
  { TCP_Opt_Corruption, "Corr",       "",                      NULL, NULL },
  { TCP_Opt_SNAP,       "SNAP",       "",                      NULL, NULL },
  { TCP_Opt_CompFilt,   "CmpFilt",    "",                      NULL, NULL },
  { TCP_Opt_QuickStart, "QkStart",    "",                      NULL, NULL }
};

#if 0
0       -       End of Option List                     [RFC793]
1       -       No-Operation                           [RFC793]
2       4       Maximum Segment Size                   [RFC793]
3       3       WSOPT - Window Scale                   [RFC1323]
4       2       SACK Permitted                         [RFC2018]
5       N       SACK                                   [RFC2018]
6       6       Echo (obsoleted by option 8)           [RFC1072]
7       6       Echo Reply (obsoleted by option 8)     [RFC1072]
8       10      TSOPT - Time Stamp Option              [RFC1323]
9       2       Partial Order Connection Permitted     [RFC1693]
10      3       Partial Order Service Profile          [RFC1693]
11              CC                                     [RFC1644]
12              CC.NEW                                 [RFC1644]
13              CC.ECHO                                [RFC1644]
14      3       TCP Alternate Checksum Request         [RFC1146]
15      N       TCP Alternate Checksum Data            [RFC1146]
16              Skeeter                                [Knowles]
17              Bubba                                  [Knowles]
18      3       Trailer Checksum Option                [Subbu & Monroe]
19      18      MD5 Signature Option                   [RFC2385]
20              SCPS Capabilities                      [Scott]
21              Selective Negative Acknowledgements    [Scott]
22              Record Boundaries                      [Scott]
23              Corruption experienced                 [Scott]
24              SNAP                                   [Sukonnik]
25              Unassigned (released 2000-12-18)
26              TCP Compression Filter                 [Bellovin]
27      8       Quick-Start Response                   [RFC4782]
28-252          Unassigned
253     N       RFC3692-style Experiment 1 (*)         [RFC4727]
254     N       RFC3692-style Experiment 2 (*)         [RFC4727]
#endif

static ptrdiff_t dump_opts(const tcp *t, const parse_frame *f, int opt, FILE *out)
{
  const u8 *cur = t->opt,
           *end = (u8 *)t + f->len;
  while (cur < end) {
    const tcp_opt *o = (tcp_opt *)cur;
    printf(" Opt #%u %-4s", o->type,
      o->type < sizeof PerOpt / sizeof PerOpt[0] ? PerOpt[o->type].shortname : "?!");
    if (TCP_Opt_End == o->type || TCP_Opt_NOP == o->type) {
      cur++;
    } else {
      printf(" len=%u ", o->len - 2);
      if (o->len > 2)
        dump_bytes((char *)o->val, o->len - 2, stdout);
      cur += o->len;
    }
    fputc('\n', stdout);
  }
#if 0
  assert(cur == end);
#endif
  return cur - (u8*)t;
}

int tcp_init(void)
{
  assert(3 == sizeof(tcp_opt));
  return 1;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[128];
} TestCase[] = {
  { 28, "\x9a\xe0\x4a\x23\xd5\xfc\x44\x7d\x00\x00\x00\x00\x70\x02\xff\xff\xa9\x79\x00\x00\x02\x04\x05\xb4\x01\x01\x04\x02" },
  { 25, "\x9a\xc6\x20\xb6\xb7""2\xfb""3\x00\x00\x00\x00p\x02\xff\xffp]\x00\x00\x02\x04\x05\xb4\x01" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_IPv4, T->len, T->txt, NULL };
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
  tcp_init();
  test();
  return 0;
}
#endif

