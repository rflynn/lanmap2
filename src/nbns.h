/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * DNS
 *
 * References:
 *
 *  #1 Network Working Group PROTOCOL STANDARD FOR A NetBIOS SERVICE ON
 *     A TCP/UDP TRANSPORT DETAILED SPECIFICATIONS [web page]
 *     <URL: http://tools.ietf.org/rfc/rfc1002.txt> [Accessed Dec 29 2008]
 *
 */

#ifndef NBNS_H
#define NBNS_H

#include "types.h"
#include "dns.h"

#define NBNS_UDP_PORT 137

/**
 * @ref #1 S4.2.1.1
 *
4.2.1.1.  HEADER
 *
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         NAME_TRN_ID           | OPCODE  |   NM_FLAGS  | RCODE |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          QDCOUNT              |           ANCOUNT             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          NSCOUNT              |           ARCOUNT             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef dns nbns;

enum NBNS_Type {
  NBNS_Type_A       = 0x0001,
  NBNS_Type_NS      = 0x0002,
  NBNS_Type_NULL    = 0x000A,
  NBNS_Type_NB      = 0x0020,
  NBNS_Type_NBSTAT  = 0x0021
};

enum NBNS_Class {
  NBNS_Class_Zero   = 0x0000,
  NBNS_Class_IN     = 0x0001
};

#endif

