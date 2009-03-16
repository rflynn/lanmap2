/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * SNMP
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "udp.h"
#include "snmp.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_SNMP = {
  DINIT(id,           PROT_SNMP),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "SNMP"),
  DINIT(propername,   "Simple Network Management Protocol"),
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

static int test_udp(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = st->frame[st->frames-1].off;
  return SNMP_UDP_PORT == u->srcport
      || SNMP_UDP_PORT == u->dstport;
}

static size_t do_parse(u8 *, size_t, parse_frame *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  tlv *t = (tlv *)buf;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *t > len)
    return 0;
  if (2u + t->len > len)
    return 0;
  bytes = do_parse(t->val, len - 2u, f);
  if (bytes)
    bytes += 2u;
  return bytes;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  char commbuf[64];
  const tlv *t = f->off;
  const struct snmp_save *s = f->pass;
  dump_chars_buf(commbuf, sizeof commbuf, (char *)s->community->val, s->community->len);
  int bytes = fprintf(out,
    "%s version=%u community=%s\n"
    " Parse this... ",
    Iface_SNMP.shortname, s->version->val[0], commbuf);
  bytes += dump_chars((char *)s->pdu->val, s->pdu->len, out);
  fputc('\n', out);
  bytes++;
  return (size_t)bytes;
}

static size_t tlv_parse(u8 *buf, size_t len)
{
  const tlv *t = (tlv *)buf;
  size_t bytes;
  assert(len >= 2u);
  bytes = 2u + t->len;
  if (bytes > len)
    bytes = len;
  return bytes;
}

static size_t tlv_dump(const tlv *t, FILE *out)
{
  int used = fprintf(out, "t=%u l=%u ", t->type, t->len);
  used += dump_chars((char *)t->val, t->len, out);
  return (size_t)used;
}

static struct snmp_save Save;
static size_t do_parse(u8 *buf, size_t len, parse_frame *f)
{
  const u8 *obuf = buf; /* save original pos */
  size_t olen = len,
         bytes = 0;
  f->pass = NULL;
  if (len) {
    Save.version = (tlv *)buf;
    bytes = tlv_parse(buf, len);
    buf += bytes, len -= bytes;
  } else {
    Save.version = NULL;
  }
  if (len) {
    Save.community = (tlv *)buf;
    bytes = tlv_parse(buf, len);
    buf += bytes, len -= bytes;
  } else {
    Save.community = NULL;
  }
  if (len) {
    Save.pdu = (tlv *)buf;
    bytes = tlv_parse(buf, len);
    buf += bytes, len -= bytes;
  } else {
    Save.pdu = NULL;
  }
  assert(bytes == 2u + Save.pdu->len);
  //assert(0u == len);
  f->pass = &Save;
  return olen;
}

#ifdef TEST

static char Sample[78] =
"\x30\x4c\x02\x01\x00"
"\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x3f\x02\x02\x0f\xc6\x02\x01\x00\x02\x01\x00\x30\x33\x30\x0f\x06\x0b\x2b\x06\x01\x02\x01\x19\x03\x02\x01\x05\x01\x05\x00\x30\x0f\x06\x0b\x2b\x06\x01\x02\x01\x19\x03\x05\x01\x01\x01\x05\x00\x30\x0f\x06\x0b\x2b\x06\x01\x02\x01\x19\x03\x05\x01\x02\x01\x05\x00";

static void test(void)
{
  parse_frame pf = { PROT_SNMP, sizeof Sample, Sample, NULL };
  parse(pf.off, pf.len, &pf, NULL);
  dump(&pf, 0, stdout);
}

int main(void)
{
  test();
  return 0;
}

#endif

