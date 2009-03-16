/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * BOOTP
 *
 * References:
 *
 *  #1 Croft, Bill RFC 951 BOOTSTRAP PROTOCOL (BOOTP) [web page]
 *    Sep 1985 <URL: http://tools.ietf.org/rfc/rfc951.txt [Accessed 18 Dec 2008]
 *  #2 Droms, R. RFC 2131: Dynamic Host Configuation Protocol [web page]
 *    March 1997 <URL: http://tools.ietf.org/rfc/rfc2131.txt [Accessed 18 Dec 2008]
 *
 */

#ifndef BOOTP_H
#define BOOTP_H

#include "types.h"
#include "ieee802_3.h"
#include "ipv4.h"

#define BOOTP_UDP_PORT_SERVER 67  /* server port */
#define BOOTP_UDP_PORT_CLIENT 68  /* client port */

/**
 * @ref #1 S 3
 */
#pragma pack(push, 1)
struct bootp {
  u8                  op,
                      htype,
                      hlen,
                      hops;
  u32                 xid;
  u16                 secs,
                      unused;
  ipv4_addr           ciaddr,
                      yiaddr,
                      siaddr,
                      giaddr;
  ieee802_3_mac_addr  chaddr;
  s8                  sname[64],
                      file[128],
                      wtf[10], /* FIXME: i'm getting something wrong here */
                      cookie[4],
  /* begin variable-length arguments */
                      opt[1];
};
#pragma pack(pop)
typedef struct bootp bootp;

enum Op {
  Op_NONE,
  Op_BOOTREQUEST,
  Op_BOOTREPLY,
  Op_COUNT
};

/**
 * @ref #3 S9.6
 * @ref #2 S3.1.2
 */
enum Type {
  DHCPDISCOVER = 1,
  DHCPOFFER,
  DHCPREQUEST,
  DHCPDECLINE,
  DHCPACK,
  DHCPNAK,
  DHCPRELEASE,
  DHCPINFORM
};

#pragma pack(push, 1)
struct bootp_opt {
  u8  opt,
      len;
};
#pragma pack(pop)
typedef struct bootp_opt bootp_opt;

enum Opt {
  OPT_SUBNET_MASK    =  1,
  OPT_ROUTER         =  3,
  OPT_DNS_SERVER     =  6,
  OPT_HOSTNAME       = 12,
  OPT_DOMAIN         = 15,
  OPT_IP_REQ         = 50,
  OPT_LEASE_TIME     = 51,
  OPT_MSG_TYPE       = 53,
  OPT_SERVER_ID      = 54,
  OPT_PARAM_REQ_LIST = 55,
  OPT_TIME_RENEW     = 58,
  OPT_TIME_REBIND    = 59,
  OPT_VENDOR_CLASS   = 60,
  OPT_STOP           = 0xFF
};

/**
 * a fingerprint of a BOOTP msg; this is constructed and stored
 * in our database as a hint
 */
struct bootp_fingerprint {
  int       ttl;
  enum Type type;
  char      vendorclass[256];
  struct octlist {
    unsigned  len;
    u8        opt[256];
  } flags, reqflags;
};
typedef struct bootp_fingerprint bootp_fingerprint;


#endif

