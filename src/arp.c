/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Address Resolution Protocol
 *
 * Ref:
 *  #1 RFC 826
 *  #2 http://www.iana.org/assignments/arp-parameters/
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "report.h"
#include "ipv4.h"
#include "arp.h"

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump (const parse_frame *, int options, FILE *);

static int test_ieee802_3(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IEEE802_3, test_ieee802_3 }
};

/**
 * exported interface
 */
const prot_iface Iface_ARP = {
  DINIT(id,           PROT_ARP),
  DINIT(osi,          OSI_Link),
  DINIT(shortname,    "ARP"),
  DINIT(propername,   "Address Resolution Protocol"),
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

static int test_ieee802_3(const char *buf, size_t len, const parse_status *st)
{
  const ethernet2_frame *f = (ethernet2_frame *)st->frame[st->frames-1].off;
  return 0x0806 == f->lentype;
}

static size_t       arp_bytes(const arp *);
static const char * arp_sha  (const arp *);
static const char * arp_spa  (const arp *);
static const char * arp_tha  (const arp *);
static const char * arp_tpa  (const arp *);

/**
 * Validate that we have minimum requirements for an ARP header:
 *
 * @return number of octets used by this protocol, or zero upon error
 */
size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  arp *a = (arp *)buf;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *a > len) /* len too short to even check length */
    return 0;
  bytes = arp_bytes(a);   /* calculate full header length */
  if (len < bytes)        /* len too short to contain full header */
    return 0;
  /* convert endianness */
  a->htype = ntohs(a->htype);
  a->ptype = ntohs(a->ptype);
  a->oper  = ntohs(a->oper);
  return bytes;
}

static const char * opstr(u16 op);
static const char * htype_dump(u16 htype, char *, size_t, const char *, size_t);
static const char * ptype_dump(u16 htype, char *, size_t, const char *, size_t);

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  char shabuf[64],
       spabuf[64],
       thabuf[64],
       tpabuf[64];
  const arp *a = (arp *)f->off;
  int bytes = fprintf(out,
    "%s htype=0x%04hx ptype=0x%04hx hlen=%u plen=%u oper=%hu(%s) "
    "sha=%s spa=%s tha=%s tpa=%s\n",
    Iface_ARP.shortname, a->htype, a->ptype, a->hlen, a->plen, a->oper, opstr(a->oper),
    htype_dump(a->htype, shabuf, sizeof shabuf, arp_sha(a), a->hlen),
    ptype_dump(a->ptype, spabuf, sizeof spabuf, arp_spa(a), a->plen),
    htype_dump(a->htype, thabuf, sizeof thabuf, arp_tha(a), a->hlen),
    ptype_dump(a->ptype, tpabuf, sizeof tpabuf, arp_tpa(a), a->plen));

#ifndef TEST
  if (0 != strcmp("0.0.0.0", spabuf))
    rep_addr("M", shabuf, "4", spabuf, "ARP", 1);
#endif

#if 0
  printf("%s %s sha:", __FILE__, __func__);
  dump_chars(arp_sha(a), a->hlen, stdout);
  fputc('\n', stdout);
  printf("%s %s spa:", __FILE__, __func__);
  dump_chars(arp_spa(a), a->plen, stdout);
  fputc('\n', stdout);
  printf("%s %s tha:", __FILE__, __func__);
  dump_chars(arp_tha(a), a->hlen, stdout);
  fputc('\n', stdout);
  printf("%s %s tpa:", __FILE__, __func__);
  dump_chars(arp_tpa(a), a->plen, stdout);
  fputc('\n', stdout);
#endif
  return (size_t)bytes;
}

/**
 * calculate the length of an ARP header in bytes
 * @note assumes network byte order
 */
static size_t arp_bytes(const arp *a)
{
  return sizeof *a + 2 * (a->hlen + a->plen);
}

static const char * arp_sha(const arp *a)
{
  return (char *)a + sizeof *a;
}

static const char * arp_spa(const arp *a)
{
  return (char *)a + sizeof *a + a->hlen;
}

static const char * arp_tha(const arp *a)
{
  return (char *)a + sizeof *a + a->hlen + a->plen;
}

static const char * arp_tpa(const arp *a)
{
  return (char *)a + sizeof *a + a->hlen + a->plen + a->hlen;
}

static const char *OPStr[ARP_OP_COUNT] = {
  "(0)",
  "Req",
  "Reply",
  "RARP-Req",
  "RARP-Reply"
  "DRARPReq",
  "DRARPRep",
  "DRARPErr",
  "InARPReq",
  "InARPRep",
  "ARPNAK",
  "MARSReq",
  "MARSMulti",
  "MARSMServ",
  "MARSJoin",
  "MARSLeave",
  "MARSNAK",
  "MARSUnserv",
  "MARSSJoin",
  "MARSSLeave",
  "MARSGrpReq",
  "MARSGrpRep",
  "MARSRedirMap",
  "MAPOSUNARP"
};

static const char * opstr(u16 op)
{
  if (op >= sizeof OPStr / sizeof OPStr[0])
    return "?";
  return OPStr[op];
}

static int init(void)
{
  printf("sizeof(arp) -> %u\n", (unsigned)sizeof(arp));
  assert(8 == sizeof(arp));
  assert(0 == offsetof(arp, htype));
  assert(2 == offsetof(arp, ptype));
  assert(4 == offsetof(arp, hlen));
  assert(5 == offsetof(arp, plen));
  assert(6 == offsetof(arp, oper));
  return 1;
}

static size_t arp_ieee802_3_dump(char *dst, size_t dstlen, const char *src, size_t srclen)
{
  return ieee802_3_addr_format(dst, dstlen, src);
}

static const struct arp_htype {
  enum ARP_HTYPE id;
  const char *descr;
  size_t (*dump)(char *, size_t, const char *, size_t);
} HType[ARP_HTYPE_COUNT] = {
  { 0,                          "(0)",                dump_chars_buf      },
  { ARP_HTYPE_Ethernet,         "Ethernet",           arp_ieee802_3_dump  },
  { ARP_HTYPE_ExpEthernet,      "ExpEthernet",        dump_chars_buf      },
  { ARP_HTYPE_AX25,             "AX25",               dump_chars_buf      },
  { ARP_HTYPE_ProNETTokenRing,  "TokenRing",          dump_chars_buf      },
  { ARP_HTYPE_Chaos,            "Chaos",              dump_chars_buf      },
  { ARP_HTYPE_IEEE802,          "IEEE802",            dump_chars_buf      },
  { ARP_HTYPE_ARCNET,           "ARCNET",             dump_chars_buf      },
  { ARP_HTYPE_Hyperchannel,     "Hyperchannel",       dump_chars_buf      },
  { ARP_HTYPE_Lanstar,          "Lanstar",            dump_chars_buf      },
  { ARP_HTYPE_AutonetShortAddr, "Autonet Short Addr", dump_chars_buf      },
  { ARP_HTYPE_LocalTalk,        "LocalTalk",          dump_chars_buf      },
  { ARP_HTYPE_PCNetorLocalNET,  "PC Net or Local NET",dump_chars_buf      },
  { ARP_HTYPE_Ultralink,        "Ultralink",          dump_chars_buf      },
  { ARP_HTYPE_SMDS,             "SMDS",               dump_chars_buf      },
  { ARP_HTYPE_FrameRelay,       "FrameRelay",         dump_chars_buf      },
  { ARP_HTYPE_ATM,              "ATM",                dump_chars_buf      },
  { ARP_HTYPE_HDLC,             "HDLC",               dump_chars_buf      },
  { ARP_HTYPE_FibreChannel,     "FiberChannel",       dump_chars_buf      },
  { ARP_HTYPE_ATM_,             "ATM",                dump_chars_buf      },
  { ARP_HTYPE_SerialLine,       "SerialLine",         dump_chars_buf      },
  { ARP_HTYPE_ATM__,            "ATM",                dump_chars_buf      },
  { ARP_HTYPE_MILSTD188220,     "MIL STD 188220",     dump_chars_buf      },
  { ARP_HTYPE_Metricom,         "Matricom",           dump_chars_buf      },
  { ARP_HTYPE_IEEE13941995,     "IEEE 1394 1995",     dump_chars_buf      },
  { ARP_HTYPE_MAPOS,            "MAPOS",              dump_chars_buf      },
  { ARP_HTYPE_Twinaxial,        "Twinaxial",          dump_chars_buf      },
  { ARP_HTYPE_EUI64,            "EUI64",              dump_chars_buf      },
  { ARP_HTYPE_HIPARP,           "HIPARP",             dump_chars_buf      },
  { ARP_HTYPE_IPARPISO78163,    "IP ARP ISO 78163",   dump_chars_buf      },
  { ARP_HTYPE_ARPSec,           "ARPSec",             dump_chars_buf      },
  { ARP_HTYPE_IPsecTunnel,      "IPSECTunnel",        dump_chars_buf      },
  { ARP_HTYPE_Infiniband,       "Infiniband",         dump_chars_buf      },
  { ARP_HTYPE_CAI,              "CAI",                dump_chars_buf      },
  { ARP_HTYPE_Wiegand,          "Wiegand",            dump_chars_buf      },
  { ARP_HTYPE_PureIP,           "PureIP",             dump_chars_buf      }
};

static const char * htype_dump(u16 htype, char *dst, size_t dstlen, const char *src, size_t srclen)
{
  if (htype >= sizeof HType / sizeof HType[0]) {
    (void)snprintf(dst, dstlen, "htype=(%hu?!)", htype);
  } else {
    (void)(*HType[htype].dump)(dst, dstlen, src, srclen);
  }
  return dst;
}

static const char * ptype_dump(u16 ptype, char *dst, size_t dstlen, const char *src, size_t srclen)
{
  if (0x0800 == ptype) {
    (void)ipv4_addr_format(dst, dstlen, src);
  } else {
    (void)dump_bytes_buf(dst, dstlen, src, srclen);
  }
  return dst;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

