/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * UDP
 */

#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "ipv4.h"
#include "tcp.h"
#include "dce-rpc.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_tcp_port(const char *, size_t, const parse_status *);
static int test_contents(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_TCP, test_tcp_port },
  { PROT_TCP, test_contents }
};

/**
 * exported interface
 */
const prot_iface Iface_DCERPC = {
  DINIT(id,           PROT_DCERPC),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "DCERPC"),
  DINIT(propername,   "DCERPC"),
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

static int test_tcp_port(const char *buf, size_t len, const parse_status *st)
{
  const tcp *t = st->frame[st->frames-1].off;
  return MSRPC_TCP_PORT == t->dstport
      || MSRPC_TCP_PORT == t->srcport;
}

static int test_contents(const char *buf, size_t len, const parse_status *st)
{
  const dcerpc_hdr *d = (dcerpc_hdr *)buf;
  return len >= sizeof *d
    && 5 == d->maj
    && 0 == d->min
    && (
      (Type_Req  == d->type && len >= sizeof *d + sizeof(dcerpc_req)) ||
      (Type_Resp == d->type && len >= sizeof *d + sizeof(dcerpc_resp))
    );
}

static size_t parse_req (const dcerpc_hdr *, void *, size_t);
static size_t parse_resp(const dcerpc_hdr *, void *, size_t);
static size_t dump_req (const void *, size_t, FILE *);
static size_t dump_resp(const void *, size_t, FILE *);

static const struct bytype {
  enum Type type;
  const char *shortname;
  size_t (*parse)(const dcerpc_hdr *, void *, size_t);
  size_t (*dump)(const void *, size_t, FILE *);
} PerType[] = {
  { Type_Req,   "req",    parse_req,    dump_req  },
  { 1,          "1?!",    NULL,         NULL      },
  { Type_Resp,  "resp",   parse_resp,   dump_resp }
};

static size_t do_parse(void *buf, size_t len, const dcerpc_hdr *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  dcerpc_hdr *h = (dcerpc_hdr *)buf;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *h > len)
    return 0;
  len -= sizeof *h;
  bytes = do_parse(buf + sizeof *h, len, h);
  if (bytes)
    bytes += sizeof *h;
  return bytes;
}

static const struct bytype * bytype(u8 type)
{
  const struct bytype *t = NULL;
  if (type < sizeof PerType / sizeof PerType[0])
    t = PerType + type;
  return t;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const dcerpc_hdr *h = f->off;
  const void *data = (u8 *)h + sizeof *h;
  const struct bytype *t = bytype(h->type);
  int bytes = fprintf(out,
    "%s ver=%u.%u type=%u(%s) ",
    Iface_DCERPC.shortname, h->maj, h->min, h->type, t ? t->shortname : "?");
  if (t && t->dump)
    bytes += (*t->dump)(data, f->len - sizeof *h, out);
  fputc('\n', out);
  bytes++;
  return (size_t)bytes;
}

static size_t do_parse(void *buf, size_t len, const dcerpc_hdr *h)
{
  const struct bytype *t = bytype(h->type);
  size_t bytes = 0;
  if (t && t->parse)
    bytes = (*t->parse)(h, buf, len);
  return bytes;
}

static size_t parse_req(const dcerpc_hdr *h, void *buf, size_t len)
{
  dcerpc_req *r = buf;
  if (len < sizeof *r)
    return 0;
  /* adjust endianness */
  r->fraglen    = ltohs(r->fraglen);
  r->authlen    = ltohs(r->authlen);
  r->callid     = ltohl(r->callid);
  r->alloc_hint = ltohl(r->alloc_hint);
  r->contextid  = ltohl(r->contextid);
  r->opnum      = ltohl(r->opnum);
  return len;
}

static size_t parse_resp(const dcerpc_hdr *h, void *buf, size_t len)
{
  dcerpc_resp *r = buf;
  if (len < sizeof *r)
    return 0;
  /* adjust endianness */
  r->fraglen    = ltohs(r->fraglen);
  r->authlen    = ltohs(r->authlen);
  r->callid     = ltohl(r->callid);
  r->alloc_hint = ltohl(r->alloc_hint);
  r->contextid  = ltohl(r->contextid);
  r->opnum      = ltohl(r->opnum);
  return len;
}

static size_t dump_flags(const dcerpc_flags *f, FILE *out)
{
  int used = fprintf(out,
    "flags(obj=%u maybe=%u !ex=%u mplx=%u res=%u cncl=%u lst=%u 1st=%u)",
    f->object, f->maybe, f->didnotexec, f->multiplex, f->res, f->cancel, f->last, f->first);
  return (size_t)used;
}

static size_t dump_req(const void *buf, size_t len, FILE *out)
{
  const dcerpc_req *r = buf;
  size_t bytes = dump_flags(&r->flags, out);
  bytes += fprintf(out,
    " fraglen=%hu authlen=%hu callid=%lu alloc_hint=%lu context=0x%04hx op=%hu\n",
    r->fraglen, r->authlen, (unsigned long)r->callid, (unsigned long)r->alloc_hint, r->contextid, r->opnum);
  bytes += dump_bytes((char *)r->data, len - sizeof *r + 1, out);
  return bytes;
}

static size_t dump_resp(const void *buf, size_t len, FILE *out)
{
  const dcerpc_resp *r = buf;
  size_t bytes = dump_flags(&r->flags, out);
  bytes += fprintf(out,
    " fraglen=%hu authlen=%hu callid=%lu alloc_hint=%lu context=0x%04hx op=%hu\n",
    r->fraglen, r->authlen, (unsigned long)r->callid, (unsigned long)r->alloc_hint, r->contextid, r->opnum);
  bytes += dump_bytes((char *)r->data, len - sizeof *r + 1, out);
  return bytes;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[256];
} TestCase[] = {
  { 128, "\x05\x00\x00\x03\x10\x00\x00\x00\x80\x00\x10\x00\xfb\x08\x00\x00\x46\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x82\x4e\x2f\xca\x8f\x1f\x44\x4a\xa9\xe2\x4b\xc9\xf1\xbc\x34\x5a\xff\x7f\x00\x00\x00\x00\x00\x00\x21\x00\x00\x00\xb8\xa5\xea\xa5\xa5\xa4\xb7\xa5\xa1\xa4\xe5\xa5\xa3\xab\xe5\xa5\xa3\xab\xa5\x5d\x0e\x8e\x2a\xde\x6c\xa4\xa7\xa5\xa5\x1e\xa7\xa5\xa5\x00\x21\x00\xff\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x0a\x02\x0a\x00\x50\x40\x17\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" },
  { 248, "\x05\x00\x02\x03\x10\x00\x00\x00\xf8\x00\x00\x00\xfb\x08\x00\x00\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x82\x4e\x2f\xca\x8f\x1f\x44\x4a\xa9\xe2\x4b\xc9\xf1\xbc\x34\x5a\xff\x7f\x00\x00\x00\x00\x00\x00\xb7\x00\x00\x00\x16\xa5\xea\xa5\xa5\xa5\xa5\xa5\xa5\xa4\xa4\xa5\xa7\xa5\xa5\xa5\xa4\x42\x60\xb6\xa5\xa4\xa5\xa5\xa5\xa5\x65\x9d\x42\xa5\xa4\xa5\xa5\xa5\xa5\x65\x9d\x42\xa5\xa5\xa5\xa5\xa5\xa5\x25\x9d\xcb\x0e\x94\xd2\x6c\xa4\xa5\xec\xf5\xe8\x8b\xeb\xca\xd1\xc0\xa5\xaf\xaa\xa4\xa1\x25\xaf\xaa\xa4\xa1\x25\xa5\xa5\xa5\xa5\xa5\xa5\xa6\xa5\xa5\xa5\xaf\xaa\xa4\xa1\x25\xa5\xfc\xa5\xa5\xa5\xa5\xa5\x79\x02\xe5\x6d\x65\xe7\xb5\xbf\x11\x1c\xad\xa5\x8e\x8a\x44\x27\xa4\xa5\xa5\xa5\xa5\xa5\xa5\xa5\x8a\xea\x98\xe6\xe4\xf7\xe1\xec\xea\xf5\xf0\xe9\xe8\xea\xeb\xe4\xf7\xfc\x85\xe6\xea\xf7\xf5\x8a\xea\xf0\x98\xe6\xea\xf7\xf5\xea\xf7\xe4\xf1\xe0\x8a\xe6\xeb\x98\xf7\xe0\xe6\xec\xf5\xec\xe0\xeb\xf1\xf6\x8a\xe6\xeb\x98\xf7\xe3\xe9\xfc\xeb\xeb\xa5\x1e\xa7\xa5\xa5\x52\xb7\x00\x00\x00\x00\x00\x00\x00" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_DCERPC, T->len, T->txt, NULL };
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

