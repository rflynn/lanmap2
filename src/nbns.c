/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * NBNS - NetBIOS Nameservice
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "ipv4.h"
#include "udp.h"
#include "dns.h"
#include "nbdgm.h"
#include "nbns.h"

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump (const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_NBNS = {
  DINIT(id,           PROT_NBNS),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "NBNS"),
  DINIT(propername,   "NetBIOS Name Service"),
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

static int test_udp(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = (udp *)st->frame[st->frames-1].off;
  return NBNS_UDP_PORT == u->dstport
      || NBNS_UDP_PORT == u->srcport;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  return dns_parse(buf, len, f, st);
}

static const char *QRStr[2][2] = {
  { "q", "Query"    },
  { "r", "Response" }
};

static size_t dump_qd(const char *buf, size_t len, FILE *out);

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const nbns *n = (nbns *)f->off;
  const char *buf = (char *)n + sizeof *n;
  size_t len = f->len - sizeof *n;
  u16 cnt;
  int bytes = fprintf(out, /* header */
    "%s %s "
    "op=%u aa=%u tc=%u rd=%u ra=%u aauth=%u "
    "cnt(qd=%u an=%u ns=%u ar=%u)\n",
    Iface_NBNS.shortname, QRStr[n->qr][0],
    n->opcode, n->aa, n->tc, n->rd, n->ra, n->aauth,
    n->qdcnt, n->ancnt, n->nscnt, n->arcnt);
  cnt = n->qdcnt; /* queries */
  while (cnt--) {
    size_t l = dns_calc_len_qd(buf, len);
    bytes += dump_qd(buf, len, out);
    buf += l, len -= l;
  }
  return (size_t)bytes;
}

static const char * type2str(u16);
static const char * class2str(u16);

static size_t dump_qd(const char *buf, size_t len, FILE *out)
{
  char namebuf[1024];
  int bytes = 0;
  const char *name = (const char *)buf;
  size_t namel = dns_calc_len_name(name, len);
  if (namel >= 2) {
    const dns_query *q = (dns_query *)(buf + namel + 1);
    namel = nb_decode_name(namebuf, sizeof namebuf, buf+1, namel-2);
    bytes = fprintf(out, " qd name=\"%.*s\" type=%hu(%s) class=%hu(%s)\n", 
      (int)namel, namebuf,
      ltohs(q->type), type2str(ltohs(q->type)),
      ltohs(q->class_), class2str(ltohs(q->class_)));
  }
  return bytes;
}

/**
 * @note tied to the order of enum DNS_Type
 */
static const struct nbns_qtype {
  enum NBNS_Type type;
  const char descr[8];
} Type[] = {
  { 0x00,                 "0x00?"     },
  { NBNS_Type_A,          "A"         },
  { NBNS_Type_NS,         "NS"        },
  { 0x03,                 "0x03?"     },
  { 0x04,                 "0x04?"     },
  { 0x05,                 "0x05?"     },
  { 0x06,                 "0x06?"     },
  { 0x07,                 "0x07?"     },
  { 0x08,                 "0x08?"     },
  { 0x09,                 "0x09?"     },
  { NBNS_Type_NULL,       "NULL"      },
  { 0x0B,                 "0x0B?"     },
  { 0x0C,                 "0x0C?"     },
  { 0x0D,                 "0x0D?"     },
  { 0x0E,                 "0x0E?"     },
  { 0x0F,                 "0x0F?"     },
  { 0x10,                 "0x10?"     },
  { 0x11,                 "0x11?"     },
  { 0x12,                 "0x12?"     },
  { 0x13,                 "0x13?"     },
  { 0x14,                 "0x14?"     },
  { 0x15,                 "0x15?"     },
  { 0x16,                 "0x16?"     },
  { 0x17,                 "0x17?"     },
  { 0x18,                 "0x18?"     },
  { 0x19,                 "0x19?"     },
  { 0x1A,                 "0x1A?"     },
  { 0x1B,                 "0x1B?"     },
  { 0x1C,                 "0x1C?"     },
  { 0x1D,                 "0x1D?"     },
  { 0x1E,                 "0x1E?"     },
  { 0x1F,                 "0x1F?"     },
  { NBNS_Type_NB,         "NB"        },
  { NBNS_Type_NBSTAT,     "NBSTAT"    }
};

/**
 * @ref #1 S4.2.1.2
 */
static struct dns_class {
  enum NBNS_Class cl;
  const char *shortname,
             *longname;
} Class[2] = {
  { 0,                  "?",    "?"           },
  { DNS_Class_IN,       "IN",   "Internet"    }
};

/**
 * ensure contiguous matching ids on Type entries
 */
static void check_types(void)
{
  unsigned i;
  printf("checking Types... "); fflush(stdout);
  for (i = 0; i < sizeof Type / sizeof Type[0]; i++) {
    printf("0x%02x ", i);
    fflush(stdout);
    assert(Type[i].type == i);
  }
  fputc('\n', stdout);
}

static void sanity_check(void)
{
  assert(12 == sizeof(nbns));
  assert(34 == sizeof Type / sizeof Type[0]);
  check_types();
}

static int init(void)
{
  sanity_check();
  return 1;
}

/**
 * convert a u16 'type' value to a human-readable string
 */
static const char * type2str(u16 t)
{
  const char *s = "?";
  if (t < sizeof Type / sizeof Type[0])
    s = Type[t].descr;
  return s;
}

/**
 * convert a u16 'class' value to a human-readable string
 */
static const char * class2str(u16 c)
{
  if (c >= sizeof Class / sizeof Class[0])
    return "?";
  return Class[c].shortname;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[1024];
} TestCase[] = {
  { 281, "\xac\xe3\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x20""CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01\x00\x00\x00\x00\x00\xd1\x09PLUTO\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x00""D\x00""EARTH\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x00\xc4\x00""EARTH\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x1c\xc4\x00PLUTO\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20""D\x00""EARTH\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x1b""D\x00PLUTO\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x03""D\x00""EARTH\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x1e\xc4\x00""EARTH\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x1d""D\x00\x01\x02__MSBROWSE__\x02\x01\xc4\x00\x00\x11""C0\x20M\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" },
  { 52, "C+\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20""ABACFPFPENFDECFCEPFHFDEFFPFPACAB\x00\x00\x20\x00\x01" },
  { 50, "y\x1f\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20""ABACFPFPENFDECFCEPFHFDEFFPFPACAB\x00\x00\x20\x00\x01" }
}, *T = TestCase;

#if 0
/*

len=92
\xff\xff\xff\xff\xff\xff\x00\x1bc\xa4\x95\xbc\x08\x00E\x00\x00N}E\x00\x00@\x11x\xa2\xc0\xa8\x01h\xc0\xa8\x01\xff\xc0\x0c\x00\x89\x00:\xb4\xf0[\xbd\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20ABACFPFPENFDECFCEPFHFDEFFPFPACAB\x00\x00\x20\x00\x01
linktype=1
parsed, len=92 bytes=14
parsed, len=78 bytes=20
test_ipv4 0x11=0x11 protocol=0x11
parsed, len=58 bytes=8
test_udp srcport=49164 dstport=137
NBNS parse failed
all done parsing
Logical id=10791 type=1 bytes=92 when=0
802.3 src=00:1b:63:a4:95:bc dst=ff:ff:ff:ff:ff:ff type=2048
IPv4 v=4 ihl=5 tos(prec=0 lodel=0 hithr=0 hirel=0 ect=0 ece=0) tlen=78 id=0x7d45 flag(evil=0 dontfrag=0 morefrag=0 fragoff=0) ttl=64 prot=0x11 chksum=0x78a2 192.168.1.104 -> 192.168.1.255
UDP srcport=49164 dstport=137 length=58 chksum=0xb4f0
Trailing bytes=50 [\xbd\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20ABACFPFPENFDECFCEPFHFDEFFPFPACAB\x00\x00\x20\x00\x01


*/
#endif

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_NBNS, T->len, T->txt, NULL };
    printf("#%2u: ", i);
    dump_chars(T->txt, T->len, stdout);
    fflush(stdout);
    parse(T->txt, T->len, &pf, NULL);
    dump(&pf, 0, stdout);
    fputc('\n', stdout);
    T++;
  }
}

int main(void)
{
  init();
  test();
  return 0;
}
#endif

