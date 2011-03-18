/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2011 Ryan Flynn
 * All rights reserved.
 */
/*
 * LLDP - Link Layer Discovery Protocol
 *
 * References:
 *
 *  #1 IEEE Std 802.1AB-2005 "IEEE Standard for Local and metropolitan area networks Station and Media Access Control Connectivity Discovery" [web page]
 *     <URL: http://standards.ieee.org/getieee802/download/802.1AB-2005.pdf>
 *     [Accessed Jan 6 2009]
 *  #2 Link Layer Discovery Protocol [web page]
 *     <URL: http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol>
 *     [Accessed Jan 6 2009]
 *
 */

#ifndef LLDP_H
#define LLDP_H

#include "types.h"

/**
 * @ref #1 S8.3
 */
#define LLDP_ETH_TYPE 0x88cc
#define LLDP_ETH_DST  "\x01\x80\xc2\x00\x00\x0e"

/**
 * LLDP is structured as a list of TLV (type-length-values)
 * @ref #1 S9.4
 */
#pragma pack(push, 1)
struct lldp {
  u16 len:9,
      type:7;
  u8  val[1]; /* variable-length... */
};
#pragma pack(pop)
typedef struct lldp lldp;

/**
 * TLV types
 * @ref #1 S9.5
 */
enum Type {
  Type_EndOfMsg   =   0,
  Type_ChassisId  =   1,
  Type_PortId     =   2,
  Type_TTL        =   3,
  Type_PortDescr  =   4,
  Type_SysName    =   5,
  Type_SysDescr   =   6,
  Type_SysCapab   =   7,
  Type_MgmtAddr   =   8,
  Type_OrgSpec    = 127
};

/**
 * Basic Organization-specific TLV format
 * @ref #1 S9.6.1
 */
#pragma pack(push, 1)
struct orgspec {
  u32 subtype:8,
      oui:24;
  u8  val[1]; /* variable-length... */
};
#pragma pack(pop)
typedef struct orgspec orgspec;

#endif

