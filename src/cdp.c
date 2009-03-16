/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * CDP
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "llc.h"
#include "ieee802_3.h" /* for reporting */
#include "cdp.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_llc(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_LLC, test_llc }
};

/**
 * exported interface
 */
const prot_iface Iface_CDP = {
  DINIT(id,           PROT_CDP),
  DINIT(osi,          OSI_Link),
  DINIT(shortname,    "CDP"),
  DINIT(propername,   "Cisco Discovery Protocol"),
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

static int test_llc(const char *buf, size_t len, const parse_status *st)
{
  const llc *l = (llc *)st->frame[st->frames-1].off;
  const llc_pid *p = llc_getpid(l);
  if (p) {
    printf("%s %s 0x%04x vs. pid=0x%04x\n",
      __FILE__, __func__, LLC_PID_CDP, p->pid);
  }
  return p && LLC_PID_CDP == p->pid;
}

static const  cdp_data D;
static void   do_parse_addrs(const cdp_data *, char *, size_t);
static void   do_parse_capab(const cdp_data *, char *, size_t);
static size_t do_dump_str   (const cdp_data *, const char *, size_t, FILE *);
static size_t do_dump_addrs (const cdp_data *, const char *, size_t, FILE *);
static size_t do_dump_capab (const cdp_data *, const char *, size_t, FILE *);
static size_t do_dump_duplex(const cdp_data *, const char *, size_t, FILE *);
static void   do_rep_softver (const parse_frame *, const char *, size_t);
static void   do_rep_platform(const parse_frame *, const char *, size_t);

/**
 * table describing each data section
 */
static const struct {
  enum Data id;
  const char *name;
  void (*parse)(const cdp_data *, char *, size_t);
  size_t (*dump)(const cdp_data *, const char *, size_t, FILE *);
  void (*rep)(const parse_frame *, const char *, size_t);
} DataHandle[Data_COUNT] = {
  { Data_0,         "(0)",      NULL,               NULL,           NULL            },
  { Data_DevID,     "DevID",    NULL,               do_dump_str,    NULL            },
  { Data_Addrs,     "Addrs",    do_parse_addrs,     do_dump_addrs,  NULL            },
  { Data_PortID,    "PortId",   NULL,               do_dump_str,    NULL            },
  { Data_Capab,     "Capab",    do_parse_capab,     do_dump_capab,  NULL            },
  { Data_SoftVer,   "SoftVer",  NULL,               do_dump_str,    do_rep_softver  },
  { Data_Platform,  "Platform", NULL,               do_dump_str,    do_rep_platform },
  { Data_7,         "(7)",      NULL,               NULL,           NULL            },
  { Data_8,         "(8)",      NULL,               NULL,           NULL            },
  { Data_9,         "(9)",      NULL,               NULL,           NULL            },
  { Data_A,         "(A)",      NULL,               NULL,           NULL            },
  { Data_Duplex,    "Duplex",   NULL,               NULL,           NULL            }
};

static size_t do_parse(char *buf, size_t len)
{
  const char *obuf = buf;
  cdp_data *d = (cdp_data *)buf;
  while (len >= sizeof d->head) {
    d->head.type = ntohs(d->head.type);
    d->head.bytes = ntohs(d->head.bytes);
    if (d->head.bytes > len)
      break;
    if (d->head.type < Data_COUNT && DataHandle[d->head.type].parse) {
      (*DataHandle[d->head.type].parse)(d, (char *)d + sizeof d->head,
                                  d->head.bytes - sizeof d->head);
      printf("%s %s (len=%u) bytes=%hu contents=",
        __FILE__, __func__, (unsigned)len, d->head.bytes);
      dump_chars((char *)d, d->head.bytes, stdout);
      fputc('\n', stdout);
    }
    len -= d->head.bytes;
    d = (cdp_data *)((char *)d + d->head.bytes);
  }
  return (size_t)((char *)d - obuf);
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  cdp *c = (cdp *)buf;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *c > len)
    return 0;
  /* convert endianness */
  c->chksum = ntohs(c->chksum);
  bytes = do_parse(buf + sizeof *c, len - sizeof *c);
  bytes += sizeof *c;
  assert(bytes == len);
  return bytes;
}

static size_t do_dump(const parse_frame *pf, const char *buf, size_t len, FILE *out)
{
  const char *obuf = buf;
  cdp_data *d = (cdp_data *)buf;
  size_t bytes = 0;
  while (len >= sizeof d->head) {
    if (d->head.bytes > len)
      break;
    if (d->head.type < Data_COUNT && DataHandle[d->head.type].dump) {
      fprintf(out, " %s=", DataHandle[d->head.type].name);
      bytes += (*DataHandle[d->head.type].dump)(d, (char *)d + sizeof d->head,
                                        d->head.bytes - sizeof d->head, out);
    }
    if (d->head.type < Data_COUNT && DataHandle[d->head.type].rep) {
      (*DataHandle[d->head.type].rep)(pf, (char *)d + sizeof d->head,
                                        d->head.bytes - sizeof d->head);
    }
    len -= d->head.bytes;
    d = (cdp_data *)((char *)d + d->head.bytes);
  }
  return bytes;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const cdp *c = (cdp *)f->off;
  int bytes = fprintf(out,
    "%s ver=%u ttl=%u chksum=0x%04x",
    Iface_CDP.shortname, c->version, c->ttl, c->chksum);
  bytes += do_dump(f, (char *)c + sizeof *c, f->len - sizeof *c, out);
  fputc('\n', out);
  bytes++;
  return (size_t)bytes;
}

static size_t do_dump_str(const cdp_data *d, const char *data, size_t len, FILE *out)
{
  int bytes = fprintf(out, "\"%.*s\"", (unsigned)len, data);
  return (size_t)bytes;
}

/**
 * report the connection between the MAC address and the 'Platform' hint
 */
static void do_rep_softver(const parse_frame *pf, const char *data, size_t len)
{
  if (PROT_LLC == (*(pf-1)).id && PROT_IEEE802_3 == (*(pf-2)).id) {
    char macbuf[32];
    const parse_frame *fe = pf-2;
    const ethernet2_frame *e = fe->off;
    assert(PROT_IEEE802_3 == fe->id);
    (void)ieee802_3_addr_format(macbuf, sizeof macbuf, &e->src);
    rep_hint("M", macbuf, "CDP.Softver", data, len);
  } else {
    assert(0 && "Where is CDP's ethernet?!");
  }
}

/**
 * report the connection between the MAC address and the 'Platform' hint
 */
static void do_rep_platform(const parse_frame *pf, const char *data, size_t len)
{
  if (PROT_LLC == (*(pf-1)).id && PROT_IEEE802_3 == (*(pf-2)).id) {
    char macbuf[32];
    const parse_frame *fe = pf-2;
    const ethernet2_frame *e = fe->off;
    assert(PROT_IEEE802_3 == fe->id);
    (void)ieee802_3_addr_format(macbuf, sizeof macbuf, &e->src);
    rep_hint("M", macbuf, "CDP.Platform", data, len);
  } else {
    assert(0 && "Where is CDP's ethernet?!");
  }
}

/**
 * given a cdp_addr, calculate the length of this variable-length field
 */
static size_t addr_offset(const struct cdp_addr *a, size_t len, int endian)
{
  size_t bytes = sizeof a->type + sizeof a->len;
  if (len > bytes) {
    const struct cdp_addr_addr *ax;
    if (Addr_Type_802_2 == a->type)
      bytes += sizeof a->prot._8022;
    else
      bytes += sizeof a->prot.nlpid;
    ax = (struct cdp_addr_addr *)((char *)a + bytes);
    if (endian)
      ((struct cdp_addr_addr *)ax)->len = ntohs(ax->len);
    bytes += sizeof ax->len + ax->len;
  }
  assert(bytes <= len);
  return bytes;
}

static void do_parse_addrs(const cdp_data *d, char *data, size_t len)
{
  struct cdp_addrs *as = (struct cdp_addrs *)data;
  if (sizeof as->cnt > len)
    return;
  as->cnt = ntohl(as->cnt);
  printf("%s %u as->cnt=%lu\n", __func__, __LINE__, (unsigned long)as->cnt);
  if (as->cnt > 0 && len >= CDP_ADDR_MINBYTES) {
    struct cdp_addr *a = &as->addr;
    struct cdp_addr_addr *aa = (struct cdp_addr_addr *)((char *)a + addr_offset(a, len, 1));
    aa->len = ntohs(aa->len);
  }
}

static void do_parse_capab(const cdp_data *d, char *data, size_t len)
{
  u32 *u = (u32 *)data;
  if (len >= sizeof *u)
    *u = ntohl(*u);
}


static const struct addr_prot_descr {
  enum Addr_Prot id;
  enum Addr_Type type;
  unsigned len;
  const char *shortname,
             *longname;
} Addr[] = {
  { Addr_Prot_ISO_CLNS,     Addr_Type_NLPID,  1, "CLNS",      "ISO CLNS"        },
  { Addr_Prot_IP,           Addr_Type_NLPID,  1, "IP",        "IP"              },
  { Addr_Prot_XNS,          Addr_Type_802_2,  8, "XNS",       "XNS"             },
  { Addr_Prot_Pv6,          Addr_Type_802_2,  8, "Pv6",       "Pv6"             },
  { Addr_Prot_DECNET4,      Addr_Type_802_2,  8, "DECNET",    "DECNET Phase IV" },
  { Addr_Prot_ApolloDomain, Addr_Type_802_2,  8, "Domain",    "Apollo Domain"   },
  { Addr_Prot_AppleTalk,    Addr_Type_802_2,  8, "AppleTalk", "AppleTalk"       },
  { Addr_Prot_BanyanVINES,  Addr_Type_802_2,  8, "VINES",     "Banyan VINES"    },
  { Addr_Prot_NovellIPX,    Addr_Type_802_2,  8, "IPX",       "Novell IPX"      }
};

const struct addr_prot_descr * addr_prot_match(const struct cdp_addr *a)
{
  const struct addr_prot_descr *s = NULL;
  unsigned i;
  for (i = 0; i < sizeof Addr / sizeof Addr[0]; i++) {
    if ((1 == a->len && Addr_Type_NLPID == Addr[i].type && Addr[i].id == a->prot.nlpid)
      || ((3 == a->len || 8 == a->len) && Addr_Type_802_2 == Addr[i].type && Addr[i].id == a->prot._8022.id)) {
      s = Addr + i;
      break;
    }
  }
  return s;
}

static size_t do_dump_addrs(const cdp_data *d, const char *data, size_t len, FILE *out)
{
  struct cdp_addrs *as = (struct cdp_addrs *)data;
  u32 cnt = as->cnt;
  int bytes = fprintf(out, "cnt=%lu", (unsigned long)as->cnt);
  assert(cnt < 5);
  while (cnt--) {
    const struct cdp_addr *a = (struct cdp_addr *)&as->addr;
    bytes += fprintf(out, "(type=%u len=%u", a->type, a->len);
    if (1 == a->len && Addr_Type_NLPID == a->type && Addr_Prot_IP == a->prot.nlpid) {
      struct cdp_addr_addr *aa = (struct cdp_addr_addr *)((char *)a + sizeof a->type + sizeof a->len + sizeof a->prot.nlpid);
      if (4 == aa->len) {
        const u8 *ip = (u8 *)aa->data;
        bytes += fprintf(out, " ip=%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
      }
    }
    fputc(')', out);
    bytes++;
    a = (struct cdp_addr *)((char *)a + addr_offset(a, len - ((char *)a - data), 0));
  }
  return (size_t)bytes;
}

static size_t do_dump_capab(const cdp_data *d, const char *data, size_t len, FILE *out)
{
  static const struct {
    u32 val;
    const char *descr;
  } Flag[] = {
    { 0x01, "Router"      },
    { 0x02, "TransBridge" },
    { 0x04, "SrcRtBridge" },
    { 0x08, "Switch"      },
    { 0x10, "Host"        },
    { 0x20, "IGMP"        },
    { 0x40, "Repeater"    }
  };
  u32 *u = (u32 *)data;
  unsigned i;
  int bytes = 1;
#if 0
  printf("%s %s *u=0x%08lx\n", __FILE__, __func__, (unsigned long)*u);
#endif
  fputc('(', out);
  for (i = 0; i < sizeof Flag / sizeof Flag[0]; i++)
    if (Flag[i].val & *u)
      bytes += fprintf(out, "%s%s", bytes > 1 ? " " : "", Flag[i].descr);
  fputc(')', out);
  bytes++;
  return (size_t)bytes;
}

static size_t do_dump_duplex(const cdp_data *d, const char *data, size_t len, FILE *out)
{
  static const struct {
    enum Duplex id;
    const char *descr;
  } Dup[Duplex_COUNT] = {
    { Duplex_Half, "half" },
    { Duplex_Full, "full" }
  };
  int bytes;
  if (d->d.duplex >= sizeof Dup / sizeof Dup[0])
    bytes = fprintf(out, "?");
  else
    bytes = fprintf(out, Dup[d->d.duplex].descr);
  return (size_t)bytes;
}

#ifdef TEST

#include <string.h>

static const struct test {
  const char *in,
             *out;
} TestCase[] = {
  {
    "0000   02 b4 6e 57 00 01 00 13 53 45 50 30 30 31 46 36  ..nW....SEP001F6\n"
    "0010   43 38 30 35 39 43 33 00 02 00 11 00 00 00 01 01  C8059C3.........\n"
    "0020   01 cc 00 04 c0 a8 49 9f 00 03 00 0a 50 6f 72 74  ......I.....Port\n"
    "0030   20 32 00 04 00 08 00 00 00 90 00 05 00 11 53 43   2............SC\n"
    "0040   43 50 34 31 2e 38 2d 33 2d 33 53 00 06 00 17 43  CP41.8-3-3S....C\n"
    "0050   69 73 63 6f 20 49 50 20 50 68 6f 6e 65 20 37 39  isco IP Phone 79\n"
    "0060   34 31 00 0b 00 05 00                             41.....",
    "CDP ver=2 ttl=180 chksum=0x6e57 DevID=\"SEP001F6C8059C3\" Addrs=cnt=1(type=1 len=1 ip=192.168.73.159) Capab=(Host) SoftVer=\"SCCP41.8-3-3S\" Platform=\"Cisco IP Phone 7941\"\n"
  }
};

/**
 * process 'TestCase' cases: parse hex->binary, parse/dump, compare dump to expected
 */
static void test(void)
{
  unsigned i, passed = 0;
  FILE *f = tmpfile();
  if (NULL == f) {
    perror("tmpfile");
  } else {
    for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
      char inbuf[1024];
      size_t inlen = decode_hex_dump(inbuf, sizeof inbuf, TestCase[i].in, strlen(TestCase[i].in));
      printf("before:\n%s\n", TestCase[i].in);
      printf("after:\n");
      dump_bytes(inbuf, inlen, stdout);
      fputc('\n', stdout);
      if (inlen) {
        char outbuf[1024];
        size_t outlen;
        parse_frame pf = { PROT_CDP, inlen, inbuf, NULL };
        int match;
        rewind(f);
        parse(inbuf, inlen, &pf, NULL);
        dump(&pf, 0, f);
        fflush(f);
        rewind(f);
        if (NULL == fgets(outbuf, sizeof outbuf, f)) {
          perror("fgets");
          break;
        }
        match = 0 == strcmp(TestCase[i].out, outbuf);
        passed += match;
        printf("#%u\n"
              "expected=%s"
              "received=%s"
              "%s\n",
              i,
              TestCase[i].out,
              outbuf,
              match ? "OK" : "!!");
      }
    }
  }
  fclose(f);
  i = sizeof TestCase / sizeof TestCase[0];
  printf("Passed=%u/%u\n",
    passed, i);
  assert(passed == i);
}

int main(void)
{
  test();
  return 0;
}
#endif

