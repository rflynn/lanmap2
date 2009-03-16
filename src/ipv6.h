/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Internet Protocol v6
 *
 * Ref:
 *  #1
 *
 */

#ifndef IPv6_H
#define IPv6_H

#include "types.h"

/**
 * a 128-bit IPv6 address
 */
typedef u8 ipv6_addr[16];
#define IPv6_ADDR_BUFLEN  40 /* longest: "0000:0000:0000:0000:0000:0000:0000:0000"
                              * shortest: "::" */

struct ipv6_addr_mask {
  ipv6_addr ip;
  unsigned  bits;
};
typedef struct ipv6_addr_mask ipv6_addr_mask;

/**
 *
 */
typedef struct ipv6 ipv6;
#pragma pack(push, 1)
struct ipv6 {
#if 0
  u32 flowlbl:20, /* QoS, unused(?) */
      trafcls:8,  /* packet priority */
      version:4;  /* version, always 6 */
#else
  u32 version:4,  /* version, always 6 */
      trafcls:8,  /* packet priority */
      flowlbl:20; /* QoS, unused(?) */
#endif
  u16 payloadlen; /* length of payload data */
  u8  nexthdr,    /* code describing next encapsulated protocol */
      hoplimit;   /* ttl */
  ipv6_addr src,
            dst;
};
#pragma pack(pop)

int    ipv6_addr_cmp   (const void *, const void *);
size_t ipv6_addr_format(char *buf, size_t len, const void *addr);
int    ipv6_addr_local (const void *addr);

#endif

