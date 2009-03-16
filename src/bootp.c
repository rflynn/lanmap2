/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * BOOTP
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h> /* offsetof() */
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "report.h"
#include "ieee802_3.h"
#include "ipv4.h"
#include "udp.h"
#include "bootp.h"

static const bootp Bootp;

static int    init(void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp_port(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp_port }
};

/**
 * exported interface
 */
const prot_iface Iface_BOOTP = {
  DINIT(id,           PROT_BOOTP),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "BOOTP"),
  DINIT(propername,   "BOOTSTRAP PROTOCOL"),
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

static int test_udp_port(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = st->frame[st->frames-1].off;
  printf("%s srcport=%hu dstport=%hu\n",
    __func__, u->srcport, u->dstport);
  return (
    /* server -> client */
    (BOOTP_UDP_PORT_SERVER == u->srcport &&
     BOOTP_UDP_PORT_CLIENT == u->dstport) ||
    /* client -> server */
    (BOOTP_UDP_PORT_CLIENT == u->srcport &&
     BOOTP_UDP_PORT_SERVER == u->dstport));
}

static size_t do_dump_str(const char *buf, size_t len, FILE *out)
{
  dump_chars(buf, len, out);
  return len;
}

static size_t do_dump_ipv4(const char *buf, size_t len, FILE *out)
{
  size_t olen = len,
         bytes = 0;
  while (len >= 4) {
    bytes += fprintf(out, "%s%u.%u.%u.%u",
      len != olen ? " " : "",
      (u8)buf[0], (u8)buf[1], (u8)buf[2], (u8)buf[3]);
    buf += 4, len -= 4;
  }
  return bytes;
}

static const struct opt_descr {
  enum Opt id;
  const char *name;
  size_t (*dump)(const char *, size_t, FILE *);
} PerOpt[] = {
  { OPT_SUBNET_MASK,    "Subnet Mask",    do_dump_ipv4 },
  { OPT_ROUTER,         "Router",         do_dump_ipv4 },
  { OPT_DNS_SERVER,     "DNS Server",     do_dump_ipv4 },
  { OPT_HOSTNAME,       "Hostname",       do_dump_str  },
  { OPT_DOMAIN,         "Domain",         do_dump_str  },
  { OPT_IP_REQ,         "IP Req",         do_dump_ipv4 },
  { OPT_LEASE_TIME,     "Lease Type",     do_dump_str  },
  { OPT_MSG_TYPE,       "MsgType",        do_dump_str  },
  { OPT_SERVER_ID,      "Server ID",      do_dump_ipv4 },
  { OPT_PARAM_REQ_LIST, "Param Req List", do_dump_str  },
  { OPT_TIME_RENEW,     "Renew",          do_dump_str  },
  { OPT_TIME_REBIND,    "Rebind",         do_dump_str  },
  { OPT_VENDOR_CLASS,   "Vendor Class",   do_dump_str  },
  { OPT_STOP,           "Stop",           do_dump_str  }
};

static const char * opt_descr(enum Opt id)
{
  const char *s = "?";
  unsigned i;
  for (i = 0; i < sizeof PerOpt / sizeof PerOpt[0]; i++) {
    if (PerOpt[i].id == id) {
      s = PerOpt[i].name;
      break;
    }
  }
  return s;
}

static size_t opt_dump(enum Opt id, const char *buf, size_t len, FILE *out)
{
  size_t bytes = 0;
  unsigned i;
  for (i = 0; i < sizeof PerOpt / sizeof PerOpt[0]; i++) {
    if (PerOpt[i].id == id) {
      bytes = (*PerOpt[i].dump)(buf, len, out);
      break;
    }
  }
  return bytes;
}

static const struct type_struct {
  enum Type type;
  const char  shortname[4],
             *longname;
} ByType[] = {
  { 0,            "(0)", "(0?!)"    },
  { DHCPDISCOVER, "Dis", "Discover" },
  { DHCPOFFER,    "Off", "Offer"    },
  { DHCPREQUEST,  "Req", "Request"  },
  { DHCPDECLINE,  "Dec", "Decline"  },
  { DHCPACK,      "Ack", "Ack",     },
  { DHCPNAK,      "Nak", "Nak",     },
  { DHCPRELEASE,  "Rel", "Release"  },
  { DHCPINFORM,   "Inf", "Inform"   }
};

static const struct type_struct * bytype(u8 type)
{
  const struct type_struct *t = NULL;
  if (type < sizeof ByType / sizeof ByType[0])
    t = ByType + type;
  return t;
}

static void do_parse_opt(const bootp *, const bootp_opt *, bootp_fingerprint *, const parse_status *);
static void do_rep_fingerprint(const bootp_fingerprint *, const parse_status *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  bootp_fingerprint p;
  bootp *b = (bootp *)buf;
  const char *toofar = buf + len;
  /* sanity check packet */
  if (sizeof *b > len)
    return 0;
  /* initialize fingerprint */
  p.ttl = -1;
  p.type = 0;
  p.vendorclass[0] = '\0';
  p.flags.len = 0;
  p.reqflags.len = 0;
  assert(PROT_UDP == st->frame[st->frames-1].id);
  assert(PROT_IPv4 == st->frame[st->frames-2].id);
  {
    const ipv4 *i = st->frame[st->frames-2].off;
    p.ttl = (int)i->ttl;
  }
  /* convert endianness */
  b->xid = ntohl(b->xid);
  b->secs = ntohs(b->secs);
  b->unused = ntohs(b->unused);
  /* ensure they're \0-terminated, which they should be */
  b->sname[sizeof b->sname - 1] = '\0';
  b->file[sizeof b->file - 1] = '\0';
  /* parse options... */
  printf("bootp opts len=%u\n", (unsigned)(len - (b->opt - (s8*)buf)));
  dump_chars((char *)b->opt, (unsigned)(len - (b->opt - (s8*)buf)), stdout);
  fputc('\n', stdout);
  if (len >= sizeof *b) {
    const bootp_opt *o = (bootp_opt *)b->opt;
    while (
      (char *)o <= toofar - sizeof *o /* ensure bogus data doesn't make us seek too far */
      && OPT_STOP != o->opt           /* valid end of options */
      && o->len > 0                   /* invalid condition; don't trust further data */
    ) {
      printf(" #%2u %-12s len=%u ",
        o->opt, opt_descr(o->opt), o->len);
      (void)opt_dump(o->opt, (char *)o + sizeof *o, o->len, stdout);
      fputc('\n', stdout);
      do_parse_opt(b, o, &p, st);
      o = (bootp_opt *)((char *)o + sizeof *o + o->len);
    }
    if ((char *)o >= toofar) /* bogus data made us skip too far */
      o = (bootp_opt *)(toofar - 1);
    printf("bootp opts end o=0x%02x\n", *(u8 *)o);
    do_rep_fingerprint(&p, st);
    return (char *)o - buf + 1;
  }
  return sizeof *b - sizeof b->opt;
}

/**
 * handle any processing/reporting for a bootp opt
 */
static void do_parse_opt(
  const bootp *b,
  const bootp_opt *o,
  bootp_fingerprint *p,
  const parse_status *st)
{
  char buf[256],
       macbuf[32];
  /* populate fingerprint and reporting */
  if (p->flags.len < sizeof p->flags.opt / sizeof p->flags.opt[0])
    p->flags.opt[p->flags.len++] = o->opt;
#ifndef TEST
  switch ((enum Opt)o->opt) {
  case OPT_MSG_TYPE:
    p->type = *((u8 *)o + sizeof *o);
    break;
  case OPT_VENDOR_CLASS:
    (void)dump_chars_buf(buf, sizeof buf, (char *)o + sizeof *o, o->len);
    strlcpy(p->vendorclass, buf, sizeof p->vendorclass);
    if (st->frames >= 3 && PROT_IEEE802_3 == st->frame[st->frames-3].id) {
      const ethernet2_frame *e = st->frame[st->frames-3].off;
      (void)ieee802_3_addr_format(macbuf, sizeof macbuf, &e->src);
      rep_hint("M", macbuf, "BOOTP.VendorClass", buf, -1);
    }
    break;
  case OPT_HOSTNAME:
    if (st->frames >= 3 && PROT_IEEE802_3 == st->frame[st->frames-3].id) {
      const ethernet2_frame *e = st->frame[st->frames-3].off;
      (void)ieee802_3_addr_format(macbuf, sizeof macbuf, &e->src);
      (void)dump_chars_buf(buf, sizeof buf, (char *)o + sizeof *o, o->len);
      rep_addr("M", macbuf, "BH", buf, "BOOTP", 1);
    }
    break;
  case OPT_PARAM_REQ_LIST:
    { /* build a list of parameter requests as part of the fingerprint */
      u8 l = o->len;
      const u8 *param = (u8 *)o + sizeof *o;
      while (l--)
        p->reqflags.opt[p->reqflags.len++] = *param++; 
    }
    break;
  default:
    break;
  }
#endif
}

static void octlist2str(char *dst, size_t dstlen, const struct octlist *l)
{
  unsigned i;
  int off = 0;
  if (l->len)
    off = snprintf(dst, dstlen, "%u", l->opt[0]);
  for (i = 1; off >= 0 && off < (int)dstlen && i < l->len; i++)
    off += snprintf(dst+off, dstlen-off, ",%u", l->opt[i]);
}

static char * fp2str(char *dst, size_t dstlen, const bootp_fingerprint *p)
{
  char typstr[16],
       flgstr[256],
       reqstr[256];
  const struct type_struct *t = bytype(p->type);
  /* string-ize type */
  if (t) {
    strlcpy(typstr, t->shortname, sizeof typstr);
  } else {
    snprintf(typstr, sizeof typstr, "%d", p->type);
  }
  /* string-ize flags */
  octlist2str(flgstr, sizeof flgstr, &p->flags);
  /* string-ize reqflags */
  octlist2str(reqstr, sizeof reqstr, &p->reqflags);
  /* put it all together */
  snprintf(dst, dstlen, "%d,%s,\"%s\",\"%s\"", p->ttl, typstr, flgstr, reqstr);
  return dst;
}

/**
 * convert bootp_fingerprint to a string representation suitable for the database
 * and associate it with the MAC address that sent it.
 */
static void do_rep_fingerprint(const bootp_fingerprint *p, const parse_status *st)
{
  char fpbuf[1024],
       macbuf[32];
  const ethernet2_frame *e = st->frame[st->frames-3].off;
  /* format fingerprint as string */
  assert(PROT_IEEE802_3 == st->frame[st->frames-3].id);
  fp2str(fpbuf, sizeof fpbuf, p);
  (void)ieee802_3_addr_format(macbuf, sizeof macbuf, &e->src);
  rep_hint("M", macbuf, "BOOTP.Fingerprint", fpbuf, -1);
}

static const char *OpStr[Op_COUNT] = {
  "",
  "Req",
  "Resp"
};

size_t dump(const parse_frame *f, int options, FILE *out)
{
  const bootp *b = f->off;
  int bytes = fprintf(out,
    "%s "
    "op=%u(%s) "
    "htype=%u hlen=%u hops=%u "
    "xid=0x%08lx secs=%lu unused=%lu "
    "ciaddr=%u.%u.%u.%u "
    "yiaddr=%u.%u.%u.%u "
    "siaddr=%u.%u.%u.%u "
    "giaddr=%u.%u.%u.%u "
    "chaddr=%02x:%02x:%02x:%02x:%02x:%02x "
    "sname=\"%s\" file=\"%s\" "
    "cookie=0x%02x%02x%02x%02x "
    "opt=0x%02x\n",
    Iface_BOOTP.shortname,
    b->op, (b->op < sizeof OpStr / sizeof OpStr[0] ? OpStr[b->op] : ""),
    b->htype, b->hlen, b->hops,
    (unsigned long)b->xid, (unsigned long)b->secs, (unsigned long)b->unused,
    b->ciaddr[0], b->ciaddr[1], b->ciaddr[2], b->ciaddr[3],
    b->yiaddr[0], b->yiaddr[1], b->yiaddr[2], b->yiaddr[3],
    b->siaddr[0], b->siaddr[1], b->siaddr[2], b->siaddr[3],
    b->giaddr[0], b->giaddr[1], b->giaddr[2], b->giaddr[3],
    b->chaddr.o[0], b->chaddr.o[1], b->chaddr.o[2],
    b->chaddr.o[3], b->chaddr.o[4], b->chaddr.o[5],
    /* FIXME: we're trusting that these are valid, decent strings?! */
    b->sname, b->file,
    (u8)b->cookie[0], (u8)b->cookie[1], (u8)b->cookie[2], (u8)b->cookie[3], 
    b->opt[0]);
  return (size_t)bytes;
}

/**
 * check the alignment and size of the packet structures
 * have had trouble with this in the past
 */
static void sanity_check(void)
{
  printf("%s:sanity_check... ", __FILE__);
  fflush(stdout);
  assert(sizeof(bootp_opt) == 2);
  assert(  0 == offsetof(bootp, op));
  assert(  1 == offsetof(bootp, htype));
  assert(  2 == offsetof(bootp, hlen));
  assert(  3 == offsetof(bootp, hops));
  assert(  4 == offsetof(bootp, xid));
  assert(  8 == offsetof(bootp, secs));
  assert( 10 == offsetof(bootp, unused));
  assert( 12 == offsetof(bootp, ciaddr));
  assert( 16 == offsetof(bootp, yiaddr));
  assert( 20 == offsetof(bootp, siaddr));
  assert( 24 == offsetof(bootp, giaddr));
  assert( 28 == offsetof(bootp, chaddr));
  assert( 34 == offsetof(bootp, sname));
  assert( 98 == offsetof(bootp, file));
  assert(128 == sizeof(Bootp.file));
  printf("offsetof(bootp, cookie) -> %u\n",
    (unsigned)offsetof(bootp, cookie));
#if 0
  assert(offsetof(bootp, file) + sizeof b->file == offsetof(bootp, cookie));
  assert(226 == offsetof(bootp, cookie));
  assert(offsetof(bootp, cookie) + sizeof b->cookie == offsetof(bootp, opt));
  assert(230 == offsetof(bootp, opt));
#endif
  printf("ok.\n");
}

static int init(void)
{
  sanity_check();
  return 1;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

