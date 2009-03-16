/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Address Resolution Protocol
 *
 * Ref:
 *  #1 RFC 826
 *  #2 http://www.iana.org/assignments/arp-parameters/
 */

#ifndef ARP_H
#define ARP_H

#include "types.h"
#include "ieee802_3.h"
#include "ipv4.h"

/**
 * ARP
 *
 */
#pragma pack(push, 1)
struct arp {
  u16 htype,    /* hardware type */
      ptype;    /* protocol type */
  u8  hlen,     /* hardware length */
      plen;     /* protocol length */
  u16 oper;     /* operation */

};
#pragma pack(pop)
typedef struct arp arp;

/**
 * Hardware types
 * @ref #2 
 */
enum ARP_HTYPE {
  ARP_HTYPE_Ethernet        =  1,
  ARP_HTYPE_ExpEthernet     =  2,
  ARP_HTYPE_AX25            =  3,
  ARP_HTYPE_ProNETTokenRing =  4,
  ARP_HTYPE_Chaos           =  5,
  ARP_HTYPE_IEEE802         =  6,
  ARP_HTYPE_ARCNET          =  7,
  ARP_HTYPE_Hyperchannel    =  8,
  ARP_HTYPE_Lanstar         =  9,
  ARP_HTYPE_AutonetShortAddr= 10,
  ARP_HTYPE_LocalTalk       = 11,
  ARP_HTYPE_PCNetorLocalNET = 12,
  ARP_HTYPE_Ultralink       = 13,
  ARP_HTYPE_SMDS            = 14,
  ARP_HTYPE_FrameRelay      = 15,
  ARP_HTYPE_ATM             = 16,
  ARP_HTYPE_HDLC            = 17,
  ARP_HTYPE_FibreChannel    = 18,
  ARP_HTYPE_ATM_            = 19,
  ARP_HTYPE_SerialLine      = 20,
  ARP_HTYPE_ATM__           = 21,
  ARP_HTYPE_MILSTD188220    = 22,
  ARP_HTYPE_Metricom        = 23,
  ARP_HTYPE_IEEE13941995    = 24,
  ARP_HTYPE_MAPOS           = 25,
  ARP_HTYPE_Twinaxial       = 26,
  ARP_HTYPE_EUI64           = 27,
  ARP_HTYPE_HIPARP          = 28,
  ARP_HTYPE_IPARPISO78163   = 29,
  ARP_HTYPE_ARPSec          = 30,
  ARP_HTYPE_IPsecTunnel     = 31,
  ARP_HTYPE_Infiniband      = 32,
  ARP_HTYPE_CAI             = 33,
  ARP_HTYPE_Wiegand         = 34,
  ARP_HTYPE_PureIP          = 35,
  ARP_HTYPE_COUNT
};

/**
 * Operation Codes
 * @ref #2
 */
enum ARP_OP {
  ARP_OP_Req          =  1,
  ARP_OP_Rep          =  2,
  ARP_OP_RReq         =  3,
  ARP_OP_RRep         =  4,
  ARP_OP_DRARPReq     =  5,
  ARP_OP_DRARPRep     =  6,
  ARP_OP_DRARPErr     =  7,
  ARP_OP_InARPReq     =  8,
  ARP_OP_InARPRep     =  9,
  ARP_OP_ARPNAK       = 10,
  ARP_OP_MARSReq      = 11,
  ARP_OP_MARSMulti    = 12,
  ARP_OP_MARSMServ    = 13,
  ARP_OP_MARSJoin     = 14,
  ARP_OP_MARSLeave    = 15,
  ARP_OP_MARSNAK      = 16,
  ARP_OP_MARSUnserv   = 17,
  ARP_OP_MARSSJoin    = 18,
  ARP_OP_MARSSLeave   = 19,
  ARP_OP_MARSGrpReq   = 20,
  ARP_OP_MARSGrpRep   = 21,
  ARP_OP_MARSRedirMap = 22,
  ARP_OP_MAPOSUNARP   = 23,
  ARP_OP_COUNT /* last, special */
};

/**
 * Protocol types
 */
enum ARP_PTYPE {
  ARP_PTYPE_IP        = 0x0800
};

u16 arp_len(const arp *a);

#endif

