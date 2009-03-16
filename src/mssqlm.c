/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * MSSQLM
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "ipv4.h"
#include "udp.h"
#include "mssqlm.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp_port(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp_port }
};

/**
 * exported interface
 */
const prot_iface Iface_MSSQLM = {
  DINIT(id,           PROT_MSSQLM),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "MSSQLM"),
  DINIT(propername,   "Microsoft SQL Server Monitor"),
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

static int test_udp_port(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = st->frame[st->frames-1].off;
  return MSSQLM_UDP_PORT == u->srcport;
}

static size_t do_parse(char *buf, size_t len, parse_frame *);
static size_t do_dump_report(const struct kv_list *, FILE *);

static void report(const parse_frame *, const parse_status *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  size_t bytes;
  /* sanity check packet */
  if (0 == len)
    return 0;
  bytes = do_parse(buf, len, f);
  if (f->pass)
    report(f, st);
  return bytes;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const mssqlm *m = f->off;
  int bytes = fprintf(out,
    "%s %s\n",
    Iface_MSSQLM.shortname,
    Code_Inquire == m->code ? "Inquire" : (Code_Report == m->code ? "Report" : "?"));
  if (Code_Report == m->code)
    bytes += do_dump_report(f->pass, out);
  return (size_t)bytes;
}

/**
 * consume a single token of the pattern "[^;]*;", write it's start and 
 * length in 'p' and return the total number of bytes consumed
 */
static size_t do_parse_token(char *buf, size_t len, ptrlen *p)
{
  size_t bytes;
  p->start = buf;
  bytes = memcspn(buf, len, ";", 1);
  p->len = bytes;
  if (bytes < len)
    bytes++;
  return bytes;
}

/**
 * MSSQLM is a simple set of variable-length key/value pairs, each value separated by ";"
 */
static size_t do_parse(char *buf, size_t len, parse_frame *f)
{
  static struct kv_list kvl;
  const mssqlm *m = (mssqlm *)buf;
  const char *orig = buf,
             *end  = buf + len;
  struct kv *k = kvl.kv;

  if (m->code != Code_Report) {
    /* don't really handle anything else right now */
    return len;
  }

  if (len < 3)
    return 0;
  buf += 3, len -= 3;

  f->pass = &kvl;
  kvl.cnt = 0;
  while (buf < end && len > 0 && kvl.cnt < sizeof kvl.kv / sizeof kvl.kv[0]) {
    size_t l;
    l = do_parse_token(buf, len, &k->key);
    buf += l, len -= l;
    if (l > 1) { /* end is an empty key ";" */
      l = do_parse_token(buf, len, &k->val);
      buf += l, len -= l;
    }
    kvl.cnt++;
    k++;
  }
  return (size_t)(buf - orig);
}

static size_t do_dump_report(const struct kv_list *l, FILE *out)
{
  int bytes;
  unsigned i;
  for (i = 0; i < l->cnt; i++)
    bytes += fprintf(out, "  %-14.*s %.*s\n",
      l->kv[i].key.len, l->kv[i].key.start,
      l->kv[i].val.len, l->kv[i].val.start);
  return (size_t)bytes;
}

/**
 * if 'kv' contains a known hint-able piece of data, report it
 */
static void do_report_hint(const struct kv *kv, const char *ipbuf)
{
  static const struct {
    size_t      len;
    const char *key,
               *hintsrc;
  } Hintable[] = {
    { 10, "ServerName",   "MSSQLM.ServerName"   },
    { 12, "InstanceName", "MSSQLM.InstanceName" },
    {  7, "Version",      "MSSQLM.Version"      },
    {  3, "tcp",          "MSSQLM.TCPPort"      },
    {  3, "udp",          "MSSQLM.UDPPort"      },
    {  2, "np",           "MSSQLM.NamedPipe"    }
  };
  unsigned i;
  for (i = 0; i < sizeof Hintable / sizeof Hintable[0]; i++) {
    if (Hintable[i].len == kv->key.len &&
        0 == memcmp(Hintable[i].key, kv->key.start, Hintable[i].len)) {
      rep_hint("4", ipbuf, Hintable[i].hintsrc, kv->val.start, kv->val.len);
    }
  }
}

static void report(const parse_frame *f, const parse_status *st)
{
  const mssqlm *m = f->off;
  if (Code_Report == m->code) {
#ifndef TEST
    if (st->frames >= 3) {
      char ipbuf[48];
      const parse_frame *fi = st->frame+st->frames-2;
      const ipv4 *ip = fi->off;
      const struct kv_list *l = f->pass;
      assert(PROT_IPv4 == fi->id);
      (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
      unsigned i;
      for (i = 0; i < l->cnt; i++) {
        do_report_hint(l->kv+i, ipbuf);
      }
    }
#endif
  }
}

#ifdef TEST

static struct {
  size_t len;
  char *txt;
} TestCase[] = {
  { 281, "\x05\x16\x01ServerName;EXTRALARGE;InstanceName;SQLEXPRESS;IsClustered;No;Version;9.00.1399.06;tcp;1073;np;\\\\EXTRALARGE\\pipe\\MSSQL$SQLEXPRESS\\sql\\query;;ServerName;EXTRALARGE;InstanceName;BERNOULLI;IsClustered;No;Version;9.00.1399.06;tcp;1433;np;\\\\EXTRALARGE\\pipe\\MSSQL$BERNOULLI\\sql\\query;;" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_MSSQLM, T->len, T->txt, NULL };
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

