/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * CDP - Cisco Discovery Protocol
 *
 * References:
 *  #1 Cisco, "Frame Formats" [web page]
 *  <URL: http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.pdf>
 *  [Accessed Dec 30 2008] (Local cache: ref/Cisco-Frame-Formats.pdf)
 *
 */

#ifndef CDP_H
#define CDP_H

#include "types.h"
#include "ipv4.h"

/**
 *
 */
#pragma pack(push, 1)
struct cdp {
  u8  version,
      ttl;      /* seconds */
  u16 chksum;
};
#pragma pack(pop)
typedef struct cdp cdp;

struct cdp_addr_addr {
  u16 len;
  s8  data[1];
};

/**
 *
 */
#pragma pack(push, 1)
struct cdp_data {
  struct {
    u16 type,
        bytes;
  } head;
  union {
    /**
     * Addrs
     * @ref #1 Table A-1
     */
    struct cdp_addrs {
      u32 cnt;
      struct cdp_addr {
        u8  type,
            len;
        union cdp_addr_prot {
          u8 nlpid;
          struct {
            u32 AAAA0300;
            u32 id;
          } _8022;
        } prot;
      } addr;
    } addrs;
    
    /**
     * Capab
     * @ref #1 Table A-2
     */
    struct cdp_capab {
      u32 router:1,
          transbridge:1,
          srcrtbridge:1,
          switch_:1,
          host:1,
          igmp:1,
          repeater:1,
          _:25;
    } capab;
    /**
     * 
     */
    u8 duplex;
  } d;
};
#pragma pack(pop)
typedef struct cdp_data cdp_data;

#define CDP_ADDR_MINBYTES \
  2+1+2+4

/**
 * Address Types; families
 * @ref #1 Table A-1
 */
enum Addr_Type {
  Addr_Type_NLPID = 1,
  Addr_Type_802_2 = 2
};

/**
 * Address Protocols
 * @ref #1 Table A-1
 */
enum Addr_Prot {
  Addr_Prot_ISO_CLNS      = 0x81,
  Addr_Prot_IP            = 0xCC,
  Addr_Prot_XNS           = 0x0600,
  Addr_Prot_Pv6           = 0x0800,
  Addr_Prot_DECNET4       = 0x6003,
  Addr_Prot_ApolloDomain  = 0x8019,
  Addr_Prot_AppleTalk     = 0x809B,
  Addr_Prot_BanyanVINES   = 0x80c4,
  Addr_Prot_NovellIPX     = 0x8137
};

/**
 *
 */
enum Data {
  Data_0,
  Data_DevID    = 0x0001,
  Data_Addrs    = 0x0002,
  Data_PortID   = 0x0003,
  Data_Capab    = 0x0004,
  Data_SoftVer  = 0x0005,
  Data_Platform = 0x0006,
  Data_7,
  Data_8,
  Data_9,
  Data_A,
  Data_Duplex   = 0x000B,
  Data_COUNT
};

enum Duplex {
  Duplex_Half,
  Duplex_Full,
  Duplex_COUNT
};

#endif

