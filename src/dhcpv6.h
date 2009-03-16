/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * DHCPv6
 *
 * References:
 *
 *  #1 Droms, R. RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
 *     July 2003 [web page] <URL: http://www.ietf.org/rfc/rfc3315.txt>
 *     [Accessed Jan 9 2009]
 *
 */

#ifndef DHCPv6_H
#define DHCPv6_H

#include "types.h"
#include "ieee802_3.h"
#include "ipv6.h"

/**
 * Multicast addresses
 * @ref #1 S5.1
 */
#define All_DHCP_Relay_Agents_and_Servers "FF02::1:2" /* A link-scoped */
#define All_DHCP_Servers                  "FF05::1:3" /* A site-scoped multicast address used */

/**
 * UDP Ports
 * @ref #1 S5.2
 */
#define DHCPv6_UDP_PORT_CLIENT  546
#define DHCPv6_UDP_PORT_SERVER  547

/**
 * Fixed-width header, very minimal.
 * All the 
 * @ref #1 S6
 */
#pragma pack(push, 1)
struct dhcpv6 {
  u8  msgtype,
      transid[3];
  /* variable-length options of format dhcpv6_opt follow... */
};
#pragma pack(pop)
typedef struct dhcpv6 dhcpv6;

/**
 * @ref #1 S5.3
 */
enum MsgType {
  SOLICIT       =  1,
  ADVERTISE     =  2,
  REQUEST       =  3,
  CONFIRM       =  4,
  RENEW         =  5,
  REBIND        =  6,
  REPLY         =  7,
  RELEASE       =  8,
  DECLINE       =  9,
  RECONFIGURE   = 10,
  INFO_REQUEST  = 11,
  RELAY_FORW    = 12,
  RELAY_REPL    = 13,
  MsgType_COUNT /* last, special */
};

/**
 * TLV (type, length, value) struct that 
 * Transmitted in network byte order.
 * @ref #1 S22.1
 */
#pragma pack(push, 1)
struct dhcpv6_opt {
  u16 code,
      len;
};
#pragma pack(pop)
typedef struct dhcpv6_opt dhcpv6_opt;

/**
 * Option codes for opt.code.
 * Unlike BOOTP/DHCP there is no 'end' option;
 * we simply stop when we run out of bytes.
 * @ref #1 S24.3
 */
enum OPTION {
  OPTION_CLIENTID       =  1,
  OPTION_SERVERID       =  2,
  OPTION_IA_NA          =  3,
  OPTION_IA_TA          =  4,
  OPTION_IAADDR         =  5,
  OPTION_ORO            =  6,
  OPTION_PREFERENCE     =  7,
  OPTION_ELAPSED_TIME   =  8,
  OPTION_RELAY_MSG      =  9,
  OPTION_AUTH           = 11,
  OPTION_UNICAST        = 12,
  OPTION_STATUS_CODE    = 13,
  OPTION_RAPID_COMMIT   = 14,
  OPTION_USER_CLASS     = 15,
  OPTION_VENDOR_CLASS   = 16,
  OPTION_VENDOR_OPTS    = 17,
  OPTION_INTERFACE_ID   = 18,
  OPTION_RECONF_MSG     = 19,
  OPTION_RECONF_ACCEPT  = 20,
  OPTION_COUNT /* last, special */
};

struct dhcpv6_fingerprint {
  int unused;
};
typedef struct dhcpv6_fingerprint dhcpv6_fingerprint;

#endif

