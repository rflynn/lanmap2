/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * Internet Group Management Protocol
 *
 * References:
 *
 *  #1 Fenner, W. RFC 2236 - Internet Group Management Protocol, Version 2
 *  November 1997 [web page] <URL: http://www.ietf.org/rfc/rfc2236.txt>
 *  [Accessed Jan 8 2009]
 *
 */

#ifndef IGMPv2_H
#define IGMPv2_H

#include "types.h"
#include "ipv4.h"

#define IGMP_IP_PROT  0x2

/**
 * @ref #1 S2
 */
#pragma pack(push, 1)
struct igmpv2 {
  u8        type,
            maxresp;
  u16       chksum;
  ipv4_addr group_addr;
};
#pragma pack(pop)
typedef struct igmpv2 igmpv2;

enum Type {
  Type_Query    = 0x11,
  Type_ReportV1 = 0x12,
  Type_ReportV2 = 0x16,
  Type_Leave    = 0x17
};

#endif

