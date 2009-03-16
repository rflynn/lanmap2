/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Linux SLL "Cooked" Capture
 */

#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "ieee802_3.h"
#include "linux_sll.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

/**
 * exported interface
 */
const prot_iface Iface_Linux_SLL = {
  DINIT(id,           PROT_LINUX_SLL),
  DINIT(osi,          OSI_Link),
  DINIT(shortname,    "Linux-SLL"),
  DINIT(propername,   "Linux SLL Cooked Capture"),
  DINIT(init,         NULL),
  DINIT(unload,       NULL),
  DINIT(parse,        parse),
  DINIT(dump,         dump),
  DINIT(addr_type,    ""),
  DINIT(addr_from,    NULL),
  DINIT(addr_to,      NULL),
  DINIT(addr_format,  NULL),
  DINIT(addr_local,   NULL),
  DINIT(parents,      0), /* being at the lowest level, we don't have a parent */
  DINIT(parent,       NULL)
};

/**
 * @return number of octets used by this protocol, or zero upon error
 */
size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  linux_sll *sll = (linux_sll *)buf;
  u16 eth_type;
  /* sanity check packet */
  if (len < sizeof *sll                 /* buffer too short */
   || (u16)ntohs(sll->packet_type) > 5  /* out of range */
   || (u16)ntohs(sll->addr_len) > 8)    /* out of range */
    return 0;
  /* check contents of eth_type for range */
  eth_type = ntohs(sll->eth_type);
  if (!IEEE802_3_IS_TYPE(eth_type)
   && Eth_Type_Novel802_3 != eth_type
   && Eth_Type_802_2 != eth_type)
    return 0;
  /* convert endianness */
  sll->packet_type = ntohs(sll->packet_type);
  sll->dev_type = ntohs(sll->dev_type);
  sll->addr_len = ntohs(sll->addr_len);
  sll->eth_type = ntohs(sll->eth_type);
  return sizeof *sll;
}

size_t dump(const parse_frame *f, int options, FILE *out)
{
  const linux_sll *sll = (linux_sll *)f->off;
  int bytes = fprintf(out,
    "%s packet_type=0x%04hx dev_type=0x%04hx addr_len=%hu "
    "addr=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
    "eth_type=0x%04hx\n",
    Iface_Linux_SLL.shortname,
    sll->packet_type, sll->dev_type, sll->addr_len,
    sll->addr[0], sll->addr[1], sll->addr[2], sll->addr[3],
    sll->addr[4], sll->addr[5], sll->addr[6], sll->addr[7],
    sll->eth_type);
  return (size_t)bytes;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

