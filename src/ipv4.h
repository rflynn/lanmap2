/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Internet Protocol
 *
 * Ref:
 *  #1 RFC 791 [web page] <URL: http://www.ietf.org/rfc/rfc791>
 *  #2 RFC 1349 [web page] <URL: http://www.ietf.org/rfc/rfc1349>
 *  #3 RFC 3514 [web page] <URL: http://www.ietf.org/rfc/rfc3514>
 */

#ifndef IPv4_H
#define IPv4_H

#include "types.h"

/**
 * a 32-bit IPv4 address
 */
typedef u8 ipv4_addr[4];

int ipv4_addr_cmp(const void *, const void *);

struct ipv4_addr_mask {
  ipv4_addr ip;
  unsigned  bits;
};
typedef struct ipv4_addr_mask ipv4_addr_mask;

/**
 * IP Options - a variable number of variable-length fields at the end of
 * an IP header.
 *  Case 1: A single octet of option-type
 *  Case 2: An option-type octet, an option-length octet, and the actual
 *          option-data octets
 * @ref #1 p.14
 */
typedef struct ipv4_opt ipv4_opt;
struct ipv4_opt {
  u8  copied:1,   /* 0=not copied 1=copied */
      class_:2,   /* see IPv4_Opt_Class */
      number:5;
  union {
    /**
     * Security
     * @ref #1 p.17-18
     */
    struct ipv4_opt_sec { /* military shit Ref #1 p.17 */
      u8  len;
      u16 S,      /* Security */
          C,      /* Compartments */
          H;      /* Handling restrictions */
      u8  TCC[3]; /* Transmission Control Code */
    } sec;

    /**
     * Strict Source and Record Route
     * @ref #1 p.19-20
     */
    struct ipv4_opt_ssrr {
      u8  len,
          ptr;  /* relative pointer from option head to next
                 * source address for use in routing. smallest
                 * legal value is 4 */
      ipv4_addr addr[1];
    } ssrr;

    /**
     * Record Route
     * @ref #1 p.20-21
     */
    struct ipv4_opt_rr {
      u8  len,
          ptr;  /* relative pointer from option head to next
                 * source address for use in routing. smallest
                 * legal value is 4 */
      ipv4_addr addr[1];
    } rr;

    /**
     * Stream Identifier
     *
     * Provide a way for the 16-bit SATNET stream identifier to be
     * carried through networks that do not support the stream concept.
     *
     * @ref #1 p.21
     */
    struct ipv4_opt_si {
      u8  len;
      u16 streamid;
    } si;

    /**
     * Internet Timestamp
     * @ref #1 p. 22-23
     */
    struct ipv4_opt_ts {
      u8  len,
          ptr,    /* pointer - number of octets from the beginning of
                   * this option to the end of the timestamps plus 1
                   * (i.e. it points to the octet beginning the space
                   * for next timestamp). The smallest legal value is
                   * 5. The timestamp area is full when the pointer is
                   * greater than the length. */
          oflw:4, /* overflow - counter of IP modules that could not
                   * include their timestamps due to lack of space */
          flg:4;  /* 0 - timestamps only, stored in consecutive 32-bit words,
                   * 1 - each timestamp is preceded with internet address of
                   *     the registering entity
                   * 3 - the internet address fields are prespecified. An
                   *     IP module only registers its timestamp if it matches
                   *     its own address with the next specified internet
                   *     address
                   */
#if 0
      u32 data[];
#endif
    } ts;

  } data;
};

/**
 * IP Option Classes
 * @ref #1 p.14
 */
enum IPv4_Opt_Class {
  IPv4_Opt_Class_Control   = 0,
  IPv4_Opt_Class_Reserved  = 1,
  IPv4_Opt_Class_Debug     = 2,
  IPv4_Opt_Class_Reserved_ = 3
};

/**
 * IP Option Numbers
 * @ref #1 p.15
 */
enum IPv4_Opt {
  IPv4_Opt_End      = 0,
  IPv4_Opt_Noop     = 1,
  IPv4_Opt_Security = 2,
  IPv4_Opt_LSRR     = 3,  /* Loose Source and Record Route */
  Ip_Opt_ITS      = 4,  /* Internet Timestamp */
  IPv4_Opt_RR       = 7,  /* Record Route */
  IPv4_Opt_StreamId = 8,
  IPv4_Opt_SSRR     = 9   /* Strict Source and Record Route */
};

/**
 * Security Option, S field (16 bit)
 * @note Specifies one of the 16 levels of security (eight of which are reserved
 * for future use)
 * @ref #1 p.16
 */
enum Ip_Opt_Sec_S {
  Ip_Opt_Sec_S_Unclassified  = 0x0000,
  Ip_Opt_Sec_S_Confidential  = 0xf135,
  Ip_Opt_Sec_S_EFTO          = 0x789a,
  Ip_Opt_Sec_S_MMMM          = 0xbc4d,
  Ip_Opt_Sec_S_PROG          = 0x5e26,
  Ip_Opt_Sec_S_Restricted    = 0xaf13,
  Ip_Opt_Sec_S_Secret        = 0xd788,
  Ip_Opt_Sec_S_TopSecret     = 0x6bc5
};

#define IPV4_IHL_MIN           20
#define IPV4_TOTLEN_MIN        20

/**
 * IP - Internet Protocol
 *
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
typedef struct ipv4 ipv4;
#pragma pack(push, 1)
struct ipv4 {
  u8        ihl:4,        /* Internet Header Length */
            version:4;    /* IP version: should be 4 */
  struct {                /* Type of Service */
    u8
            ece:1,        /* ? */
            ect:1,        /* ? */
            hirel:1,      /* High Reliability */
            hithr:1,      /* High Throughput */
            lodelay:1,    /* Low Delay */
            prec:3;       /* Precedence: see IPv4_Prec */
  } tos;
  u16       totlen,       /* Total Length: header + data */
            id;           /* ? */
  struct {
    u16 
            fragoff:13,   /* Fragment Offset: ? */
            morefrag:1,   /* More Fragments: ? */
            dontfrag:1,   /* Don't Fragment: ? */
            evil:1;       /* must be zero Ref # */
  } flag;

  u8        ttl,          /* Time To Live */
            protocol;     /* Protocol Id: Protocol payload type */
  u16       checksum;     /* Header Checksum */
  ipv4_addr src,
            dst;
  /* NOTE: Options (ipv4_opt) are optional; option parsing depends
   * on ihl being > 20 */
};
#pragma pack(pop)

/**
 * the 8 possible values for the 3-bit IP 'Precedence' field
 */
enum IPv4_Prec {
  IPv4_Prec_NetworkControl      = 7,
  IPv4_Prec_InternetworkControl = 6,
  IPv4_Prec_CRITICECP           = 5,
  IPv4_Prec_FlashOverride       = 4,
  IPv4_Prec_Flash               = 3,
  IPv4_Prec_Immediate           = 2,
  IPv4_Prec_Priority            = 1,
  IPv4_Prec_Routine             = 0
};

size_t ipv4_addr_format(char *, size_t, const void *);
int    ipv4_addr_local (const void *);

#endif

