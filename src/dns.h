/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * DNS
 *
 * References:
 *
 *  #1 Mockapetris, P. DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION [web page] <URL: http://tools.ietf.org/rfc/rfc1035.txt> [Accessed Dec 28 2008]
 *  #2 Domain Name System (DNS) Parameters [web page] <URL: http://www.iana.org/assignments/dns-parameters>
 *  #3 [web page] <URL: http://en.wikipedia.org/wiki/List_of_DNS_record_types>
 *
 */

#ifndef DNS_H
#define DNS_H

#include "types.h"

#define DNS_UDP_PORT  53
#define MDNS_UDP_PORT 5353

/**
 * @ref #1 S4.1.1
 *
 * The header contains the following fields:
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      ID                       |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    QDCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ANCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    NSCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ARCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
#pragma pack(push, 1)
struct dns {
  u16 id;
  u16 rcode:4,  /* response code 0=ok, else error */
      Z_:1,     /* reserved (must be zero) */
      aauth:1,  /* Answer Authenticated */
      Z:1,      /* reserved (must be zero) */
      ra:1,     /* Recursion Available? (resp) */
      rd:1,     /* Recursion Desired? (query) */
      tc:1,     /* TrunCated? */
      aa:1,     /* AuthoritAtive? */
      opcode:4, /* see enum DNS_Opcode */
      qr:1;     /* 0=Query, 1=Resp */
  u16 qdcnt, /* count of Response Records by type... */
      ancnt,
      nscnt,
      arcnt;
  /* variable-width data after... */
};
#pragma pack(pop)
typedef struct dns dns;

#pragma pack(push, 1)
struct dns_query {
  /* variable-length name prefix... */
  u16 type,
      class_;
};
#pragma pack(pop)
typedef struct dns_query dns_query;

#pragma pack(push, 1)
struct dns_answer {
  /* variable-length name... */
  u16 type;
  u16
      cacheflush:1, /* FIXME: MDNS (?!) */
      _:7,
      class_:8;
  s32 ttl;
  u16 rrlen;
  /* variable-length name... */
};
#pragma pack(pop)
typedef struct dns_answer dns_answer;

#pragma pack(push, 1)
struct dns_auth_suffix {
  u32 serialno,
      refresh,
      retry,
      explimit,
      minttl;
};
#pragma pack(pop)
typedef struct dns_auth_suffix dns_auth_suffix;

#if 0
#pragma pack(push, 1)
struct dns_soa_rdata {
  /* @ref #1 S3.3.13 */
  /* MNAME variable-length */
  /* RNAME variable-length */
  /* struct dns_auth_suffix */
};
#pragma pack(pop)
#endif

enum DNS_RR {
  DNS_RR_AN,
  DNS_RR_NS,
  DNS_RR_AR
};

/**
 * @ref #1 S4.1.1
 */
enum DNS_Opcode {
  DNS_Opcode_QUERY,
  DNS_Opcode_IQUERY,
  DNS_Opcode_STATUS,
  DNS_Opcode_3,
  DNS_Opcode_4,
  DNS_Opcode_5,
  DNS_Opcode_6,
  DNS_Opcode_7,
  DNS_Opcode_8,
  DNS_Opcode_9,
  DNS_Opcode_10,
  DNS_Opcode_11,
  DNS_Opcode_12,
  DNS_Opcode_13,
  DNS_Opcode_14,
  DNS_Opcode_15,
  DNS_Opcode_COUNT
};

/**
 * @ref #1 S4.1.1
 */
enum DNS_RCode {
  DNS_RCode_OK          = 0,
  DNS_RCode_FormatErr   = 1,
  DNS_RCode_ServerFail  = 2,
  DNS_RCode_NameErr     = 3,
  DNS_RCode_NotImpl     = 4,
  DNS_RCode_Refused     = 5,
  /* reserved... */
  DNS_RCode_6,         
  DNS_RCode_7,
  DNS_RCode_8,
  DNS_RCode_9,
  DNS_RCode_10,
  DNS_RCode_11,
  DNS_RCode_12,
  DNS_RCode_13,
  DNS_RCode_14,
  DNS_RCode_15,
  DNS_RCode_COUNT
};

/**
 * TYPE/QTYPE
 * @ref #1 S 3.2.2
 * @ref #2 S Registry Name: Resource Record (RR) TYPEs
 * @ref #3 (regarding current statuses of some of the more obscure types)
 */
enum DNS_Type {
  DNS_Type_A        =     1, /* a host address */
  DNS_Type_NS       =     2, /* an authoritative name server */
  DNS_Type_MD       =     3, /* a mail destination (Obsolete - use MX) */
  DNS_Type_MF       =     4, /* a mail forwarder (Obsolete - use MX) */
  DNS_Type_CNAME    =     5, /* the canonical name for an alias */
  DNS_Type_SOA      =     6, /* marks the start of a zone of authority */
  DNS_Type_MB       =     7, /* a mailbox domain name */
  DNS_Type_MG       =     8, /* a mail group member */
  DNS_Type_MR       =     9, /* a mail rename domain name */
  DNS_Type_NULL     =    10, /* a null RR */
  DNS_Type_WKS      =    11, /* a well known service description */
  DNS_Type_PTR      =    12, /* a domain name pointer */
  DNS_Type_HINFO    =    13, /* host information */
  DNS_Type_MINFO    =    14, /* mailbox or mail list information */
  DNS_Type_MX       =    15, /* mail exchange */
  DNS_Type_TXT      =    16, /* text strings */
  DNS_Type_RP       =    17, /* (unused) */
  DNS_Type_AFSDB    =    18, /* RFC 1183 */
  DNS_Type_X25      =    19, /* (unused) */
  DNS_Type_ISDN     =    20, /* (unused) */
  DNS_Type_RT       =    21, /* (unused) */
  DNS_Type_NSAP     =    22, /* (unused) */
  DNS_Type_NSAPPTR  =    22, /* (unused) */
  DNS_Type_SIG      =    24, /* RFC 2535 */
  DNS_Type_KEY      =    25, /* RFC 4034 */
  DNS_Type_PX       =    26, /* RFC 4034 */
  DNS_Type_GPOS     =    27, /* (unused) */
  DNS_Type_AAAA     =    28, /* RFC 3596 */
  DNS_Type_LOC      =    29, /* RFC 1876 */
  DNS_Type_NXT      =    30, /* Obsoleted by DNSSEC updates (RFC 3755) (Ref #3) */
  DNS_Type_EID      =    31, /* (unused) */
  DNS_Type_NIMLOC   =    32, /* (unused) */
  DNS_Type_SRV      =    33, /* RFC 2782 */
  DNS_Type_ATMA     =    34, /* (unused) */
  DNS_Type_NAPTR    =    35, /* RFC 3403 */
  DNS_Type_KX       =    36, /* Part of the first version of DNSSEC
                               * (RFC 2230 and 2065) now obsolete (Ref #3) */
  DNS_Type_CERT     =    37, /* RFC 4398 */
  DNS_Type_A6       =    38, /* downgraded to experimental by RFC 3363 (Ref #3)*/
  DNS_Type_DNAME    =    39, /* RFC 2672 */
  DNS_Type_SINK     =    40, /* (kitchen sink) */
  DNS_Type_OPT      =    41, /* RFC 2671 */
  DNS_Type_APL      =    42, /* (unused) */
  DNS_Type_DS       =    43, /* RFC 3658 */
  DNS_Type_SSHFP    =    44, /* RFC 4255 */
  DNS_Type_IPSECKEY =    45, /* RFC 4025 */
  DNS_Type_RRSIG    =    46, /* RFC 3755 */
  DNS_Type_NSEC     =    47, /* RFC 3755 */
  DNS_Type_DNSKEY   =    48, /* RFC 3755 */
  DNS_Type_DHCID    =    49, /* RFC 4701 */
  DNS_Type_NSEC3    =    50, /* RFC 5155 */
  DNS_Type_NSEC3PARAM=   51, /* RFC 5155 */
  DNS_Type_HIP      =    55, /* RFC 5205 */
  DNS_Type_SPF      =    99, /* RFC 4408 */
  DNS_Type_UINFO    =   100, /* (reserved but unused) */
  DNS_Type_UID      =   101, /* (reserved but unused) */
  DNS_Type_GID      =   102, /* (reserved but unused) */
  DNS_Type_UNSPEC   =   103, /* (reserved but unused) */
  DNS_Type_TKEY     =   249, /* RFC 2930 */
  DNS_Type_TSIG     =   250, /* RFC 2845 */
  DNS_Type_IXFR     =   251, /* RFC 1995 */
  DNS_Type_AXFR     =   252, /* A request for a transfer of an entire zone */
  DNS_Type_MAILB    =   253, /* A request for mailbox-related records (MB, MG or MR) */
  DNS_Type_MAILA    =   254, /* A request for mail agent RRs (Obsolete - see MX) */
  DNS_Type_ALL      =   255, /* A request for all records */
  DNS_Type_TA       = 32768, /* */
  DNS_Type_DLV      = 32769  /* RFC 4331 */
};

/**
 * 
 */
enum DNS_Class {
  DNS_Class_Reserved    =     0,
  DNS_Class_IN          =     1,
  DNS_Class_CH          =     3,
  DNS_Class_HS          =     4,
  DNS_Class_QCLASS_None =   254,
  DNS_Class_QCLASS_Any  =   255
};

/* exported for NBNS */
size_t dns_parse        (char *, size_t, parse_frame *, const parse_status *);
size_t dns_calc_len     (const char *, size_t, const dns *);
size_t dns_calc_len_qd  (const char *, size_t);
size_t dns_calc_len_rr  (const char *, size_t);
size_t dns_calc_len_name(const char *, size_t);

#endif

