/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * Storm Worm Botnet Traffic
 *
 * References:
 *
 *  #1 Zhang, Jun. Storm Worm & Botnet Analysis Jun 2008
 *     <URL: http://securitylabs.websense.com/content/Assets/Storm_Worm_Botnet_Analysis_-_June_2008.pdf>
 *     [Accessed 11 Jan 2009]
 *  #2 "jeremy" Decrypted Storm Worm PCAP May 19 2008
 *     <URL: http://www.sudosecure.net/wp-content/uploads/2008/05/decrypt_storm1.pcap>
 *     [Accessed 11 Jan 2009]
 *
 */

#ifndef STORMBOTNET_H
#define STORMBOTNET_H

#include "types.h"

/**
 *
 */
#pragma pack(push, 1)
struct storm_hdr {
  u8  e3,
      code;
};
#pragma pack(pop)
typedef struct storm_hdr storm_hdr;

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct botid {
  u8        hash[16];   /* 128-bit node hash */
  ipv4_addr ip;
  u16       port;
  u8        flag;       /* purpose unspecified? */
};
#pragma pack(pop)
typedef struct botid botid;

/**
 *
 */
#pragma pack(push, 1)
struct resp_hdr {
  u16 len;
};
#pragma pack(pop)
typedef struct resp_hdr resp_hdr;

/**
 * all possible values for storm.code
 * not all meanings deciphered
 */
enum Code {
  Code_Resp        = 0x0b,
  Code_Announce    = 0x0c, /* Announce ourselves */
  Code_NoPayload   = 0x0d,
  Code_23Bytes     = 0x15,
  Code_2Bytes      = 0x1b,
  Code_4Bytes      = 0x1c,
  Code_NoPayload1e = 0x1e
};

#endif

