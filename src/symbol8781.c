/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Mysterious protocol emanating from Symbol wireless access points
 * with Ethernet Type 0x8781
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "ieee802_3.h"
#include "ipv4.h"
#include "symbol8781.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_8781(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IEEE802_3, test_8781 }
};

/**
 * exported interface
 */
const prot_iface Iface_Symbol8781 = {
  DINIT(id,           PROT_SYMBOL8781),
  DINIT(osi,          OSI_Trans),
  DINIT(shortname,    "0x8781"),
  DINIT(propername,   "Symbol 8781"),
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

static int test_8781(const char *buf, size_t len, const parse_status *st)
{
  const ethernet2_frame *e = (ethernet2_frame *)st->frame[st->frames-1].off;
  printf("%s 0x8781=0x%02x lentype=0x%04x\n",
    __func__, 0x8781, e->lentype);
  return 0x8781 == e->lentype;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  symbol8781 *s = (symbol8781 *)buf;
  /* sanity check packet */
  if (sizeof *s > len)
    return 0;
  /* convert endianness */
  return sizeof *s;
}

size_t dump(const parse_frame *f, int options, FILE *out)
{
  symbol8781 *s = (symbol8781 *)f->off;
  char u0buf[65],
       u1buf[128],
       namebuf[256],
       datebuf[64],
       namelongbuf[128];
  dump_chars_buf(u0buf, sizeof u0buf, (char *)s->u0, sizeof s->u0);
  dump_chars_buf(u1buf, sizeof u1buf, (char *)s->u1, sizeof s->u1);
  dump_chars_buf(namebuf, sizeof namebuf, (char *)s->name, strlen((char *)s->name));
  dump_chars_buf(datebuf, sizeof datebuf, (char *)s->date, strlen((char *)s->date));
  dump_chars_buf(namelongbuf, sizeof namelongbuf, (char *)s->namelong, strlen((char*)s->namelong));
  int bytes = fprintf(out,
    "%s u0=%s ip=%u.%u.%u.%u u1=%s "
    "name=%s date=%s namelong=%s\n",
    Iface_Symbol8781.shortname, u0buf, s->ip[0], s->ip[1], s->ip[2], s->ip[3], u1buf,
    namebuf, datebuf, namelongbuf);
  return (size_t)bytes;
}

#ifdef TEST

/*
len=140
\x01\xa0\xf8\xf0\xf0\x02\x00\xa0\xf87\xa5\xae\x87\x81\x00-\x08\x00\x00v\x00\x00\x00\x06\x00\x07\x00\x00\x00\x01\x0a,\x16\xb5\x00\x00\x00\x00\x09+\x00\x00\x00\x00\x02\x03\x03\x00\x00\x00\x0
0\x00\x00\x01TEST\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a04.02-19\x00\x00\x00\x00\x00\x00\x0
0\x00Engineering\x20Lab,\x20TEST\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
linktype=1
parsed 802.3 len=140 bytes=14
test_ieee802_3 0x86dd=0x86dd f->lentype=0x8781
test_8781 0x8781=0x8781 lentype=0x8781
parsed 0x8781 len=126 bytes=126
all done parsing
Logical id=60 type=1 bytes=140 when=0
802.3 src=00:a0:f8:37:a5:ae dst=01:a0:f8:f0:f0:02 type=0x8781
0x8781 u0=\x00-\x08\x00\x00v\x00\x00\x00\x06\x00\x07\x00\x00\x00\x01 ip=10.44.22.181 u1=\x00\x00\x00\x00\x09+\x00\x00\x00\x00\x02\x03\x03\x00\x00\x00\x00\x00\x00\x01 name=TEST date=04.02-1
9 namelong=Engineering Lab, TEST
*/


static char Sample[] = 
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
"\x00\x00\x00\x00\x00\x00";

int main(void)
{
  parse_frame f = { PROT_IEEE802_3, sizeof Sample, Sample, NULL };
  dump(&f, 0, stdout);
  return 0;
}
#endif

