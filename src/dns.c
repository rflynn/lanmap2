/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * DNS
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "ipv4.h"
#include "ipv6.h"
#include "udp.h"
#include "dns.h"

static int    init (void);
static size_t dump (const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static int test_mdns(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp  },
  { PROT_UDP, test_mdns }
};

/**
 * exported interface
 */
const prot_iface Iface_DNS = {
  DINIT(id,           PROT_DNS),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "DNS"),
  DINIT(propername,   "Domain Name System"),
  DINIT(init,         init),
  DINIT(unload,       NULL),
  DINIT(parse,        dns_parse),
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
  return DNS_UDP_PORT == u->dstport
      || DNS_UDP_PORT == u->srcport;
}

static int test_mdns(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = (udp *)st->frame[st->frames-1].off;
  return MDNS_UDP_PORT == u->dstport
      && MDNS_UDP_PORT == u->srcport;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
size_t dns_parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  dns *d = (dns *)buf;
  size_t bytes = 0;
  /* sanity check packet */
  if (sizeof *d > len)
    return 0;
  /* convert endianness */
  d->id    = ntohs(d->id);
  d->qdcnt = ntohs(d->qdcnt);
  d->ancnt = ntohs(d->ancnt);
  d->nscnt = ntohs(d->nscnt);
  d->arcnt = ntohs(d->arcnt);
  bytes = sizeof *d + dns_calc_len(buf + sizeof *d, len - sizeof *d, d);
  printf("%s %s len=%u bytes=%u\n",
    __FILE__, __func__, (unsigned)len, (unsigned)bytes);
  //assert(bytes == len);
  return bytes;
}

static const char *QRStr[2][2] = {
  { "q", "Query"    },
  { "r", "Response" }
};

static size_t dump_qd(const char *, size_t, FILE *);
static size_t dump_rr(enum DNS_RR, const parse_frame *, const char *, size_t, FILE *);

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const dns *d = (dns *)f->off;
  const char *buf = (char *)d + sizeof *d;
  size_t len = f->len - sizeof *d;
  u16 cnt;
  int bytes = fprintf(out, /* header */
    "%s %s "
    "op=%u aa=%u tc=%u rd=%u ra=%u aauth=%u "
    "cnt(qd=%u an=%u ns=%u ar=%u)\n",
    Iface_DNS.shortname, QRStr[d->qr][0],
    d->opcode, d->aa, d->tc, d->rd, d->ra, d->aauth,
    d->qdcnt, d->ancnt, d->nscnt, d->arcnt);
  cnt = d->qdcnt; /* queries */
  while (cnt--) {
    size_t l = dns_calc_len_qd(buf, len);
    bytes += dump_qd(buf, len, out);
    buf += l, len -= l;
  }
  cnt = d->ancnt; /* answers */
  while (cnt--) {
    size_t l = dns_calc_len_rr(buf, len);
    bytes += dump_rr(DNS_RR_AN, f, buf, len, out);
    buf += l, len -= l;
  }
  cnt = d->nscnt; /* nameserver */
  while (cnt--) {
    size_t l = dns_calc_len_rr(buf, len);
    bytes += dump_rr(DNS_RR_NS, f, buf, len, out);
    buf += l, len -= l;
  }
  cnt = d->arcnt; /* additional */
  while (cnt--) {
    size_t l = dns_calc_len_rr(buf, len);
    bytes += dump_rr(DNS_RR_AR, f, buf, len, out);
    buf += l, len -= l;
  }

  return (size_t)bytes;
}

static const char * type2str(u16);
static const char * class2str(u16);

static size_t dump_qd(const char *buf, size_t len, FILE *out)
{
  char namebuf[1024];
  const char *name = (const char *)buf;
  size_t namel = memcspn(name, len, "\x00", 1);
  int bytes = 0;
  const dns_query *q = (dns_query *)(buf + namel + 1);
  (void)dump_chars_buf(namebuf, sizeof namebuf, buf, namel);
#if 0
  printf("len=%u name[namel=%u]=%s name[10]=", (unsigned)len, (unsigned)namel, namebuf);
  dump_chars(name, 10, stdout);
  fputc('\n', stdout);
#endif
  bytes = fprintf(out, " qd name=%s type=%hu(%s) class=%hu(%s)\n", 
    namebuf,
    ntohs(q->type), type2str(ntohs(q->type)),
    ntohs(q->class_), class2str(ntohs(q->class_)));
  return bytes;
}

static size_t dump_ipv4_buf(char *dst, size_t dstlen, const char *src, size_t srclen)
{
  return ipv4_addr_format(dst, dstlen, src);
}

static size_t dump_ipv6_buf(char *dst, size_t dstlen, const char *src, size_t srclen)
{
  return ipv6_addr_format(dst, dstlen, src);
}

static size_t dump_cname(char *dst, size_t dstlen, const char *src, size_t srclen)
{
  const char *odst = dst;
  while (srclen-- && dstlen--) {
    if (!(0x80 & *src) && (isalnum((int)*src) || ispunct((int)*src)))
      *dst++ = '.';
    else
      *dst++ = *src;
    src++;
  }
  return (size_t)(dst-odst);
}

static void do_rep_txt(const parse_status *st, const parse_frame *f, const char *buf, size_t len)
{
#if 0
  rep_hint("M", macbuf, "BOOTP.VendorClass", (char *)o + sizeof *o, o->len);
#endif
}

/**
 * @note tied to the order of enum DNS_Type
 */
static const struct dns_qtype {
  enum DNS_Type type;
  const char descr[12];
  size_t (*format)(char *, size_t, const char *, size_t);
  void (*rep)(const parse_status *, const parse_frame *, const char *, size_t);
} Type[] = {
  { 0,                   "(0)",       dump_chars_buf, NULL        },
  { DNS_Type_A,          "A",         dump_ipv4_buf,  NULL        },
  { DNS_Type_NS,         "NS",        dump_chars_buf, NULL        },
  { DNS_Type_MD,         "MD",        dump_chars_buf, NULL        },
  { DNS_Type_MF,         "MF",        dump_chars_buf, NULL        },
  { DNS_Type_CNAME,      "CNAME",     dump_chars_buf, NULL        },
  { DNS_Type_SOA,        "SOA",       dump_chars_buf, NULL        },
  { DNS_Type_MB,         "MB",        dump_chars_buf, NULL        },
  { DNS_Type_MG,         "MG",        dump_chars_buf, NULL        },
  { DNS_Type_MR,         "MR",        dump_chars_buf, NULL        },
  { DNS_Type_NULL,       "NULL",      dump_chars_buf, NULL        },
  { DNS_Type_WKS,        "WKS",       dump_chars_buf, NULL        },
  { DNS_Type_PTR,        "PTR",       dump_chars_buf, NULL        },
  { DNS_Type_HINFO,      "HINFO",     dump_chars_buf, NULL        },
  { DNS_Type_MINFO,      "MINFO",     dump_chars_buf, NULL        },
  { DNS_Type_MX,         "MX",        dump_chars_buf, NULL        },
  { DNS_Type_TXT,        "TXT",       dump_chars_buf, do_rep_txt  },
  { DNS_Type_RP,         "RP",        dump_chars_buf, NULL        },
  { DNS_Type_AFSDB,      "AFSDB",     dump_chars_buf, NULL        },
  { DNS_Type_X25,        "X25",       dump_chars_buf, NULL        },
  { DNS_Type_ISDN,       "ISDN",      dump_chars_buf, NULL        },
  { DNS_Type_RT,         "RT",        dump_chars_buf, NULL        },
  { DNS_Type_NSAP,       "NSAP",      dump_chars_buf, NULL        },
  { DNS_Type_NSAPPTR,    "NSAPPTR",   dump_chars_buf, NULL        },
  { DNS_Type_SIG,        "SIG",       dump_chars_buf, NULL        },
  { DNS_Type_KEY,        "KEY",       dump_chars_buf, NULL        },
  { DNS_Type_PX,         "PX",        dump_chars_buf, NULL        },
  { DNS_Type_GPOS,       "GPOS",      dump_chars_buf, NULL        },
  { DNS_Type_AAAA,       "AAAA",      dump_ipv6_buf,  NULL        },
  { DNS_Type_LOC,        "LOC",       dump_chars_buf, NULL        },
  { DNS_Type_NXT,        "NXT",       dump_chars_buf, NULL        },
  { DNS_Type_EID,        "EID",       dump_chars_buf, NULL        },
  { DNS_Type_NIMLOC,     "NIMLOC",    dump_chars_buf, NULL        },
  { DNS_Type_SRV,        "SRV",       dump_chars_buf, NULL        },
  { DNS_Type_ATMA,       "ATMA",      dump_chars_buf, NULL        },
  { DNS_Type_NAPTR,      "NAPTR",     dump_chars_buf, NULL        },
  { DNS_Type_KX,         "KX",        dump_chars_buf, NULL        },
  { DNS_Type_CERT,       "CERT",      dump_chars_buf, NULL        },
  { DNS_Type_A6,         "A6",        dump_chars_buf, NULL        },
  { DNS_Type_DNAME,      "DNAME",     dump_chars_buf, NULL        },
  { DNS_Type_SINK,       "SINK",      dump_chars_buf, NULL        },
  { DNS_Type_OPT,        "OPT",       dump_chars_buf, NULL        },
  { DNS_Type_APL,        "APL",       dump_chars_buf, NULL        },
  { DNS_Type_DS,         "DS",        dump_chars_buf, NULL        },
  { DNS_Type_SSHFP,      "SSHFP",     dump_chars_buf, NULL        },
  { DNS_Type_IPSECKEY,   "IPSECKEY",  dump_chars_buf, NULL        },
  { DNS_Type_RRSIG,      "RRSIG",     dump_chars_buf, NULL        },
  { DNS_Type_NSEC,       "NSEC",      dump_chars_buf, NULL        },
  { DNS_Type_DNSKEY,     "DNSKEY",    dump_chars_buf, NULL        },
  { DNS_Type_DHCID,      "DHCID",     dump_chars_buf, NULL        },
  { DNS_Type_NSEC3,      "NSEC3",     dump_chars_buf, NULL        },
  { DNS_Type_NSEC3PARAM, "NSEC3PARAM",dump_chars_buf, NULL        },
  { DNS_Type_HIP,        "HIP",       dump_chars_buf, NULL        },
  { DNS_Type_SPF,        "SPF",       dump_chars_buf, NULL        },
  { DNS_Type_UINFO,      "UINFO",     dump_chars_buf, NULL        },
  { DNS_Type_UID,        "UID",       dump_chars_buf, NULL        },
  { DNS_Type_GID,        "GID",       dump_chars_buf, NULL        },
  { DNS_Type_UNSPEC,     "UNSPEC",    dump_chars_buf, NULL        },
  { DNS_Type_TKEY,       "TKEY",      dump_chars_buf, NULL        },
  { DNS_Type_TSIG,       "TSIG",      dump_chars_buf, NULL        },
  { DNS_Type_IXFR,       "IXFR",      dump_chars_buf, NULL        },
  { DNS_Type_AXFR,       "AXFR",      dump_chars_buf, NULL        },
  { DNS_Type_MAILB,      "MAILB",     dump_chars_buf, NULL        },
  { DNS_Type_MAILA,      "MAILA",     dump_chars_buf, NULL        },
  { DNS_Type_ALL,        "ALL",       dump_chars_buf, NULL        },
  { DNS_Type_TA,         "TA",        dump_chars_buf, NULL        },
  { DNS_Type_DLV,        "DLV",       dump_chars_buf, NULL        }
};

size_t dns_calc_len_qd(const char *buf, size_t len)
{
  const char *name = (const char *)buf;
  size_t l = memcspn(name, len, "\x00", 1),
         bytes = l;
  if (l < len) {
    const dns_query *q = (dns_query *)(buf + l + 1);
    bytes += 1 + sizeof *q;
  }
#if 0
  assert(bytes <= len);
#endif
  if (bytes > len)
    bytes = len;
  return bytes;
}

/**
 * parse a variable-length DNS name pointed at by 'buf'; do not exceed
 * 'len' bytes
 * @ref #1 S3.1
 */
size_t dns_calc_len_name(const char *buf, size_t len)
{
  const char *obuf = buf;
  size_t olen = len;
  while (len > 0) {
    if (0xC0 == (u8)*buf) {
      if (len < 2)
        buf += len, len = 0;
      else
        buf += 2, len -= 2;
      break;
    } else if ((u8)*buf >= len) {
      buf += len, len = 0;
      break;
    } else if (0 == *buf) {
      buf++, len--;
      break;
    } else {
      len -= *buf + 1;
      buf += *buf + 1;
    }
  }
#if 0
  printf("%s name(%u bytes)=", __func__, (unsigned)(buf - obuf));
  dump_chars(obuf, (unsigned)(buf - obuf), stdout);
  fputc('\n', stdout);
#endif
  assert((size_t)(buf - obuf) <= olen);
  return (size_t)(buf - obuf);
}

size_t dns_calc_len_rr(const char *buf, size_t len)
{
  const char *name = buf;
  size_t namelen = dns_calc_len_name(name, len);
  const dns_answer *a;
  size_t bytes = len;
  if (namelen + sizeof *a > len)
    return len;
  a = (dns_answer *)(buf + namelen); 
  bytes = namelen + sizeof *a + ntohs(a->rrlen);
#if 0
  printf("name(%u byes)=", namelen);
  dump_chars(name, namelen, stdout);
  fputc('\n', stdout);
  printf("answer(%u byes)=", sizeof *a);
  dump_chars((char*)a, sizeof *a, stdout);
  fputc('\n', stdout);
#endif
  if (bytes > len)
    bytes = len;
  return bytes;
}

/**
 * given an already-overlayed and endian-adjusted 'dns' struct and the rest of
 * the packet, calculate the length of the following variable-length Response Records
 */
size_t dns_calc_len(const char *buf, size_t len, const dns *d)
{
  const struct {
    u16 cnt;
    size_t (*f)(const char *, size_t);
  } parse[4] = {
    { d->qdcnt, dns_calc_len_qd },
    { d->ancnt, dns_calc_len_rr },
    { d->nscnt, dns_calc_len_rr },
    { d->arcnt, dns_calc_len_rr }
  };
  const char *obuf = buf;
  const size_t olen = len;
  size_t bytes;
  unsigned i;
  printf("%s:%s len=%u d=%p\n", __FILE__, __func__, (unsigned)len, (void *)d);
  for (i = 0; i < sizeof parse / sizeof parse[0]; i++) {
    u16 cnt = parse[i].cnt;
    if (cnt)
      printf("%s:%s i=%u cnt=%hu\n", __FILE__, __func__, i, cnt);
    while (cnt--) {
      size_t b = (*parse[i].f)(buf, len);
      printf("%s:%s i=%u cnt=%hu consumed=%hu bytes=",
        __FILE__, __func__, i, cnt, (unsigned)b);
      dump_chars(buf, b, stdout);
      fputc('\n', stdout);
      assert(b <= len);
      /* adjust buffer/length for next pass */
      buf += b, len -= b;
    }
  }
  bytes = (size_t)(buf - obuf);
  printf("bytes=%u olen=%u\n", (unsigned)bytes, (unsigned)olen);
  if (bytes != olen)
    printf("!!! You didn't consume the whole message!\n");
  return bytes;
}

static char * addrformat(u16, char *, size_t, const char *, size_t);

static const struct {
  enum DNS_RR id;
  const char *name;
} RR[] = {
  { DNS_RR_AN,  "an" },
  { DNS_RR_NS,  "ns" },
  { DNS_RR_AR,  "ar" }
};

static size_t strip_c0(const char *s, size_t len)
{
  size_t c0 = memcspn(s, len, "\xc0\x00", 2);
  if (c0)
    c0--;
  return c0;
}

static size_t dump_rr(enum DNS_RR rr, const parse_frame *f, const char *buf, size_t len, FILE *out)
{
  char namebuf[256],
       targetbuf[256];
  const char *name = buf;
  size_t namelen = dns_calc_len_name(name, len);
  const dns_answer *a = (dns_answer *)(buf + namelen);
  int bytes;
  (void)dump_chars_buf(namebuf, sizeof namebuf, name, namelen-1);
  bytes = fprintf(out,
    " %s name=%s type=%hu(%s) class=%hu(%s) ttl=%ld target=%s\n",
    RR[rr].name, namebuf,
    ntohs(a->type), type2str(ntohs(a->type)),
    a->class_, class2str(a->class_),
    (long)ntohl(a->ttl),
    addrformat(ntohs(a->type), targetbuf, sizeof targetbuf,
                               (char *)a + sizeof *a, ntohs(a->rrlen)));
#ifndef TEST
  /* TODO: split this block off to another function */
  if (DNS_RR_AN == rr && DNS_Type_TXT == ntohs(a->type)) {
    /* is a TXT record answer; usually supplemental information that can
     * contain some interesting stuff */
    const char *addrtype = NULL;
    char ipbuf[64];
    const parse_frame *fi = f-2;
    if (PROT_IPv4 == fi->id) {
      const ipv4 *i = fi->off;
      addrtype = "4";
      ipv4_addr_format(ipbuf, sizeof ipbuf, i->src);
    } else if (PROT_IPv6 == fi->id) {
      const ipv6 *i = fi->off;
      addrtype = "6";
      ipv6_addr_format(ipbuf, sizeof ipbuf, i->src);
    }
    if (addrtype) {
      (void)dump_chars_buf(namebuf, sizeof namebuf, name,
        strip_c0(namebuf, namelen));
      (void)dump_chars_buf(targetbuf, sizeof targetbuf, (char *)a + sizeof *a,
        strip_c0((char *)a + sizeof *a, ntohs(a->rrlen)));
      if ('\0' != namebuf[0])
        rep_hint(addrtype, ipbuf, "DNS.TXT", namebuf, -1);
      if ('\0' != targetbuf[0])
        rep_hint(addrtype, ipbuf, "DNS.TXT", targetbuf, -1);
    }
  } else if (DNS_RR_AN == rr
         && (DNS_Type_A == ntohs(a->type) || DNS_Type_AAAA == ntohs(a->type))
         && str_endswith(namebuf, "\\x05local")) {
    /* we're looking for ".local" addresses; which may identify the machine */
    char ipbuf[64];
    const parse_frame *fi = f-2;
    const char *addrtype = NULL;
    if (PROT_IPv4 == fi->id) {
      const ipv4 *i = fi->off;
      addrtype = "4";
      ipv4_addr_format(ipbuf, sizeof ipbuf, i->src);
    } else if (PROT_IPv6 == fi->id) {
      const ipv6 *i = fi->off;
      addrtype = "6";
      ipv6_addr_format(ipbuf, sizeof ipbuf, i->src);
    }
    (void)dump_chars_buf(namebuf, sizeof namebuf, name, namelen-1);
    if ('\0' != namebuf[0]) {
      rep_hint(addrtype, ipbuf, "DNS.LOCAL", namebuf, -1);
    }
    {
      char localname[64];
      /* first char is length of actual name */
      if (name[0] > 0 && (unsigned)name[0] < sizeof localname) {
        strlcpy(localname, name+1, (size_t)name[0]+1); 
        localname[(unsigned)name[0]] = '\0';
      } else {
        strlcpy(localname, name+1, sizeof localname); 
      }
      rep_addr(addrtype, ipbuf, "D", localname, "DNS.LOCAL", 1);
    }
  }
#endif
  return (size_t)bytes;
}

/**
 * @ref #3
 */
static struct dns_class {
  enum DNS_Class cl;
  const char *shortname,
             *longname;
} Class[256] = {
  { DNS_Class_Reserved, "(0)",  "Reserved(0)" },
  { DNS_Class_IN,       "IN",   "Internet"    },
  { 2,                  "(2)",  "Reserved(2)" },
  { DNS_Class_CH,       "CH",   "CH"          },
  { DNS_Class_HS,       "HS",   "HS"          }
};

static void init_data_class(void)
{
  unsigned i;
  for (i = 5; i < sizeof Class / sizeof Class[0]; i++) {
    Class[i].cl = (enum DNS_Class)i;
    Class[i].shortname = "?";
    Class[i].longname = "?";
  }
  Class[DNS_Class_QCLASS_None].cl         = DNS_Class_QCLASS_None;
  Class[DNS_Class_QCLASS_None].shortname  = "None";
  Class[DNS_Class_QCLASS_None].longname   = "None";
  Class[DNS_Class_QCLASS_Any].cl          = DNS_Class_QCLASS_Any;
  Class[DNS_Class_QCLASS_Any].shortname   = "*";
  Class[DNS_Class_QCLASS_Any].longname    = "Any";
}

static void init_data(void)
{
  init_data_class();
}

static void sanity_check(void)
{
  assert(12 == sizeof(struct dns));
  assert( 4 == sizeof(struct dns_query));
  assert(10 == sizeof(struct dns_answer));
  assert(16 == DNS_Opcode_COUNT);
  assert(16 == DNS_RCode_COUNT);
}

static int init(void)
{
  sanity_check();
  init_data();
  return 1;
}

static const struct dns_qtype * dns_qtype(u16 t)
{
  const struct dns_qtype *q = NULL;
  if (t <= 51) {
    q = Type + t;
  } else {
    unsigned i = 51;
    while (i < sizeof Type / sizeof Type[0] && Type[i].type > t)
      i++;
    if (Type[i].type == t)
      q = Type + i;
  }
  return q;
}

/**
 * convert a u16 'type' value to a human-readable string
 */
static const char * type2str(u16 t)
{
  const char *s = "?";
  const struct dns_qtype *q = dns_qtype(t);
  if (q)
    s = q->descr;
  return s;
}

/**
 *
 */
static char * addrformat(u16 t, char *dst, size_t dstlen,
                                      const char *src, size_t srclen)
{
  const char *s = "?";
  const struct dns_qtype *q = dns_qtype(t);
  *dst = '\0';
  if (q)
    (*q->format)(dst, dstlen, src, srclen);
  return dst;
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
  char txt[512];
} TestCase[] = {
  { 228, "\x00\x00\x84\x00\x00\x00\x00\x06\x00\x00\x00\x00\x16Julia\x20Lin\xe2\x80\x99s\x20iMac\x20(2)\x0b_afpovertcp\x04_tcp\x05local\x00\x00!\x80\x01\x00\x00\x00x\x00\x1a\x00\x00\x00\x00\x02$\x11julia-lins-imac-2\xc0""4\xc0\x0c\x00\x10\x80\x01\x00\x00\x11\x94\x00\x01\x00\xc0#\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x02\xc0\x0c\x16Julia\x20Lin\xe2\x80\x99s\x20iMac\x20(2)\x0c_device-info\xc0/\x00\x10\x00\x01\x00\x00\x11\x94\x00\x0e\x0dmodel=iMac7,1\xc0K\x00\x01\x80\x01\x00\x00\x00x\x00\x04\xc0\xa8\x01h\xc0K\x00\x1c\x80\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x1b""c\xff\xfe\xa4\x95\xbc" },
  { 216, "\x00\x00\x84\x00\x00\x00\x00\x02\x00\x00\x00\x04\x0b_afpovertcp\x04_tcp\x05local\x00\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x19\x16Julia\x20Lin\xe2\x80\x99s\x20iMac\x20(2)\xc0\x0c\x16Julia\x20Lin\xe2\x80\x99s\x20iMac\x20(2)\x0c_device-info\xc0\x18\x00\x10\x00\x01\x00\x00\x11\x94\x00\x0e\x0dmodel=iMac7,1\xc0.\x00!\x80\x01\x00\x00\x00x\x00\x1a\x00\x00\x00\x00\x02$\x11julia-lins-imac-2\xc0\x1d\xc0.\x00\x10\x80\x01\x00\x00\x11\x94\x00\x01\x00\xc0\x97\x00\x01\x80\x01\x00\x00\x00x\x00\x04\xc0\xa8\x01h\xc0\x97\x00\x1c\x80\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x1b""c\xff\xfe\xa4\x95\xbc" },
  { 123, "Y\xb6\x81\x80\x00\x01\x00\x02\x00\x01\x00\x00\x06static\x06reddit\x03""com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00$V\x00\x0f\x02s3\x09""amazonaws\xc0\x1a\xc0/\x00\x05\x00\x01\x00\x00\x00,\x00\x07\x04s3-1\xc0""2\xc0J\x00\x06\x00\x01\x00\x00\x00\x01\x00*\x06ns-921\x06""amazon\xc0\x1a\x03""dns\xc0""dI_\xccJ\x00\x00\x0e\x10\x00\x00\x03\x84\x00v\xa7\x00\x00\x00\x00<" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_DNS, T->len, T->txt, NULL };
    printf("#%2u: ", i);
    dump_chars(T->txt, T->len, stdout);
    dns_parse(T->txt, T->len, &pf, NULL);
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

