/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Linux SLL "Cooked" Capture
 *
 * Linux-specific capture format, why?!
 *
 * Ref:
 *  #1 pcap manpage
 */

#ifndef LINUX_SLL_H
#define LINUX_SLL_H

#include "types.h"
#include "ipv4.h"
#include <net/if_arp.h> /* ARPHDR_* for dev_type field */

/**
 DLT_LINUX_SLL
  Linux "cooked" capture encapsulation; the link layer header contains, in
  order:
    a 2-byte "packet type", in network byte order, which is one of:
      0 packet was sent to us by somebody else
      1 packet was broadcast by somebody else
      2 packet was multicast, but not broadcast, by somebody else
      3 packet was sent by somebody else to somebody else
      4 packet was sent by us
    a 2-byte field, in network byte order, containing a Linux ARPHRD_ value
      for the link layer device type;
    a 2-byte field, in network byte order, containing the length of the
      link layer address of the sender of the packet (which could be 0);
    an 8-byte field containing that number of bytes of the link layer header
      (if there are more than 8 bytes, only the first 8 are present);
    a  2-byte field containing an Ethernet protocol type, in network byte
      order, or containing 1 for Novell 802.3 frames without an 802.2 LLC
      header or 4 for frames beginning with an 802.2 LLC header.
 */

/**
 * packet origins
 */
enum Packet {
  Packet_Recv,  /* packet was sent to us by somebody else */
  Packet_Bcast, /* packet was broadcast by somebody else */
  Packet_Mcast, /* packet was multicast, but not broadcast, by somebody else */
  Packet_Snoop, /* packet was sent by somebody else to somebody else */
  Packet_Local  /* packet was sent by us */
};

/**
 * special values for 'eth_type' field
 */
enum Eth_Type {
  Eth_Type_Novel802_3 = 1, /* 1 for Novell 802.3 frames without an 802.2 LLC header */
  Eth_Type_802_2      = 4, /* 4 for frames beginning with an 802.2 LLC header */
};

#pragma pack(push, 1)
struct linux_sll {
  u16   packet_type,  /* Packet_* describing packet origins */
        dev_type,     /* ARPHDR_* from net/if_arp.h */
        addr_len;     /* length of contents of 'addr' field */
  u8    addr[8];
  u16   eth_type;     /* same as ieee802_3 'lentype' field, with additional
                       * Eth_Type_* exceptions */
};
#pragma pack(pop) 
typedef struct linux_sll linux_sll;

#endif

