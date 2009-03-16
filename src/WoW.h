/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * World of Warcraft Protocol
 *
 * References:
 *
 *  #1 Avery, Jason "Decoding The World of Warcrft Protocol" Thu 28 Jun 2007 [web page]
 *     <URL: http://dvlabs.tippingpoint.com/blog/2007/06/28/decoding-the-world-of-warcraft>
 *     [Accessed Jan 11 2009]
 *
 */

#ifndef WOW_H
#define WOW_H

#include "types.h"

/*
 * @ref #1
 *
 * After enough data gathering and analysis, we can easily deduce the following
 * packet schema from the game client (version 1.7.0.4671):
 *
 * 0030                       02 22 00 57 6f 57 00 01 07          .".WoW... 
 * 0040  00 3f 12 36 38 78 00 6e 69 57 00 53 55 6e 65 98   .?.68x.niW.SUne. 
 * 0050  fe ff ff c0 a8 01 aa 04 54 45 53 54               ........TEST 
 * 
 * In little endian:
 * 02              Packet Type
 * 22 00           Length of rest of packet 
 * WoW 00          Packet Identifier: "WoW" 
 * 01              Major Version number of client program 
 * 07              Minor Version number of client program 
 * 00              Patch Version of client program 
 * 3f 12           Build Number of client ("4671")
 * 68x 00          Client Processor (either "x86" or "PPC") 
 * niW 00          Client Operating system (either "Win" or "OSX") 
 * SUne            Client Language setting ("enUS" here) 
 * 98 fe ff ff     Unknown
 * c0 a8 01 aa     Client's real IP address
 * 04              Length of the following Account Name
 * TEST            Account Name 
 */
#pragma pack(push, 1)
struct wow {
  u8  type;
  u16 len;
  u8  id[4],
  struct {
    u8        maj,
              min,
              patch;
    u16       build;
    u8        proc[4],
              os[4],
              lang[4],
              unknown[4];
    ipv4_addr ip;
    u8        acctnamelen;
    u8        acctname[1]; /* variable-length */
  } client;
};
#pragma pack(pop)
typedef struct wow wow;

#endif

