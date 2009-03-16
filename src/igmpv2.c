/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * IGMP
 */

#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "ipv4.h"
#include "igmpv2.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_ipv4(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_IPv4, test_ipv4 }
};

/**
 * exported interface
 */
const prot_iface Iface_IGMPv2 = {
  DINIT(id,           PROT_IGMPv2),
  DINIT(osi,          OSI_Net),
  DINIT(shortname,    "IGMP"),
  DINIT(propername,   "Internet Group Management Protocol"),
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

static int test_ipv4(const char *buf, size_t len, const parse_status *st)
{
  const ipv4 *ip = st->frame[st->frames-1].off;
  return IGMP_IP_PROT == ip->protocol;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  igmpv2 *i = (igmpv2 *)buf;
  /* sanity check packet */
  if (sizeof *i > len)
    return 0;
  /* convert endianness */
  i->chksum = ntohs(i->chksum);
  return sizeof *i;
}

static const struct bytype {
  enum Type type;
  const char *shortname,
             *longname;
} ByType[] = {
  { Type_Query,     "Query",    "Membership Query"        },
  { Type_ReportV1,  "Reportv1", "Membership Report (v1)"  },
  { Type_ReportV2,  "Reportv2", "Membership Report (v2)"  },
  { Type_Leave,     "Leave",    "Leave Group"             }
};

static const struct bytype * bytype(u8 type)
{
  const struct bytype *b = NULL;
  unsigned i;
  for (i = 0; i < sizeof ByType / sizeof ByType[0]; i++) {
    if (type == ByType[i].type) {
      b = ByType + i;
      break;
    }
  }
  return b;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const igmpv2 *i = f->off;
  const struct bytype *t = bytype(i->type);
  int bytes = fprintf(out,
    "%s type=0x%2x(%s) maxresp=(%u.%u sec) chksum=0x%04x group=%u.%u.%u.%u\n",
    Iface_IGMPv2.shortname, i->type, t ? t->shortname : "?",
    i->maxresp / 10, i->maxresp % 10, i->chksum,
    i->group_addr[0], i->group_addr[1], i->group_addr[2], i->group_addr[3]);
  return (size_t)bytes;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

