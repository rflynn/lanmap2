/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * types defined by IEEE 802.3
 *
 * References:
 *
 * #1 "IEEE Std 802.3.-2005" http://standards.ieee.org/getieee802/download/802.3-2005_section1.pdf
 *
 */

#ifndef IEEE802_3_H
#define IEEE802_3_H

#include "types.h"


/** @ref #1 S 3.2.2 (The SFD field is the sequence 10101011) */
#define IEEE802_3_SFD_SEQ       0xAB 

/** @ref #1 S 4.2.7.1 */
#define IEEE802_3_addressSize     48
#define IEEE802_3_headerSize      64
#define IEEE802_3_minTypeValue  1536

/**
 * @ref #1 
 */
#pragma pack(push, 1) /* align on 1-byte boundaries */
union ieee802_3_mac_addr {
  /*
   * Ref #1 Section 3.2.3 "Address fields"
   */
  u8 o[6];                    /* raw octets */
  struct ieee802_3_mac_bia {  /* "Burned-in addresses" */
    u8 oui[3],                /* Organizationally Unique Identifier */
       nic[3];                /* Network Interface Controller */
  } bia;
  struct ieee802_3_mac_laa {  /* Locally Administered Address */
    u8 multicast:1,           /* multicast=1 unicast=0 */
       local_admin:1,         /* local=1 globally unique (OUI enforced) */
       addr:6,                /* address */
       addr_[5];              /* address continued */
  } laa;
};
#pragma pack(pop)
typedef union ieee802_3_mac_addr ieee802_3_mac_addr;

int ieee802_3_mac_addr_cmp(const void *, const void *);

/**
 *
 * @note transmitted LSB first
 */
#pragma pack(push, 1) /* align on 1-byte boundaries */
struct ethernet2_frame {
#if 0 /* do i not get this? */
  u8                 preamble[7],
                     sfd[1];
#endif
  ieee802_3_mac_addr dst,
                     src;
  u16                lentype; /* either length or type */
};
#pragma pack(pop)
typedef struct ethernet2_frame ethernet2_frame;

#define IEEE802_3_IS_LEN(lt)  ((lt) < IEEE802_3_minTypeValue)
#define IEEE802_3_IS_TYPE(lt) (!IEEE802_3_IS_LEN(lt))

size_t ieee802_3_addr_format(char *s, size_t len, const void *vaddr);
int    ieee802_3_addr_local (const void *addr);

#endif

