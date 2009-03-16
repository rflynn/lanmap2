/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * NTP
 */

#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "udp.h"
#include "ntp.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_NTP = {
  DINIT(id,           PROT_NTP),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "NTP"),
  DINIT(propername,   "Network Time Protocol"),
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
  return len == sizeof(ntp)
      && NTP_UDP_PORT == u->dstport
      && NTP_UDP_PORT == u->srcport;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  ntp *n = (ntp *)buf;
  /* sanity check packet */
  if (sizeof *n > len)
    return 0;
  /* convert endianness */
  n->rootdelay  = ntohl(n->rootdelay);
  n->rootdisp   = ntohl(n->rootdisp);
  n->refid      = ntohl(n->refid);
  n->keyid      = ntohl(n->keyid);
  return sizeof *n;
}

/**
 * @ref #1 S"Mode"
 */
static const struct bymode {
  enum Mode mode;
  const char *shortname,
             *longname;
} ByMode[Mode_COUNT] = {
  { Mode_Unspec,      "unspec",   "unspecified"                       },
  { Mode_SymActive,   "symact",   "symmetric active"                  },
  { Mode_SymPassive,  "sympas",   "symmetric passive"                 },
  { Mode_Client,      "client",   "client"                            },
  { Mode_Server,      "server",   "server"                            },
  { Mode_Broadcast,   "bcast",    "broadcast"                         },
  { Mode_NTPCtrl,     "ctrl",     "reserved for NTP control messages" },
  { Mode_Private,     "private",  "reserved for private use"          }
};

static const struct bymode * bymode(u8 mode)
{
  const struct bymode *b = NULL;
  if (mode < sizeof ByMode / sizeof ByMode[0])
    b = ByMode + mode;
  return b;
}

/**
 * @ref #1 S"Mode"
 */
static const struct byleap {
  enum Leap leap;
  const char *shortname,
             *longname;
} ByLeap[] = {
  { Leap_NoWarn,      "nowarn",     "no warning"                                },
  { Leap_LastMin61,   "lastmin61",  "last minute has 61 seconds"                },
  { Leap_LastMin59,   "lastmin59",  "last minute has 59 seconds"                },
  { Leap_AlarmUnsync, "alarm",      "alarm condition (clock not synchronized)"  }
};

static const struct byleap * byleap(u8 leap)
{
  const struct byleap *l = NULL;
  unsigned i;
  for (i = 0; i < sizeof ByLeap / sizeof ByLeap; i++) {
    if (ByLeap[i].leap == leap) {
      l = ByLeap + i;
      break;
    }
  }
  return l;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const ntp *n = f->off;
  const struct bymode *m = bymode(n->mode);
  const struct byleap *l = byleap(n->leap);
  int bytes = fprintf(out,
    "%s "
    "mode=%u(%s) v=%u leap=%u(%s) stratum=%u ppoll=%u "
    "prec=%u root(dlay=0x%08lx dsp=0x%08lx) ref=0x%08lx "
    "reftime=%02x%02x%02x%02x%02x%02x%02x%02x ... "
    "keyid=0x%08lx\n",
    Iface_NTP.shortname,
    n->mode, m ? m->shortname : "?", n->version, n->leap, l ? l->shortname : "?", n->stratum, n->ppoll,
    n->precision, (unsigned long)n->rootdelay, (unsigned long)n->rootdisp, (unsigned long)n->refid,
    n->reftime[0], n->reftime[1], n->reftime[2], n->reftime[3], n->reftime[4], n->reftime[5], n->reftime[6], n->reftime[7],
    (unsigned long)n->keyid);
  return (size_t)bytes;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[69];
} TestCase[] = {
  { 68, "\x1c\x02\x0a\xfa\x00\x00\x08\x00\x00\x00\x46\x95\xc0\x05\x29\x28\xcd\x0e\x33\xda\x72\x05\xfd\x70\xcd\x0e\x3e\xde\x1d\x88\xbe\x80\xcd\x0e\x3e\xde\x25\xfd\xcc\x49\xcd\x0e\x3e\xde\x25\xfd\xcc\x49\x00\x00\x00\x00\x36\x2c\xdb\x70\xef\xa2\x59\xe3\xc5\x97\xac\x7a\x7b\xd3\xd6\x99" },
  { 68, "\x1c\x02\x0a\xfa\x00\x00\x08\x00\x00\x00F\x95\xc0\x05)(\xcd\x0e3\xdar\x05\xfdp\xcd\x0e>\xde\x1d\x88\xbe\x80\xcd\x0e>\xde%\xfd\xccI\xcd\x0e>\xde%\xfd\xccI\x00\x00\x00\x006,\xdbp\xef\xa2Y\xe3\xc5\x97\xacz{\xd3\xd6\x99" }
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_NTP, T->len, T->txt, NULL };
    printf("#%2u: ", i);
    dump_chars(T->txt, T->len, stdout);
    fputc('\n', stdout);
    parse(T->txt, T->len, &pf, NULL);
    dump(&pf, 0, stdout);
    T++;
  }
}

int main(void)
{
  test();
  return 0;
}
#endif


