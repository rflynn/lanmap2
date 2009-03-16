/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * define generic protocol-related structures and
 * a list of all supported protocols.
 */

#ifndef PROT_H
#define PROT_H

#include <stddef.h> /* size_t */
#include <stdio.h>  /* FILE */
#include "types.h"

/**
 * OSI Network Model
 */
enum OSI {
  OSI_Phys,
  OSI_Link,
  OSI_Mac,
  OSI_LLC,
  OSI_Net,
  OSI_Trans,
  OSI_Sess,
  OSI_Pres,
  OSI_App,
  OSI_Other
};

/**
 * all supported protocol ids (internal)
 */
enum Prot {
  PROT_UNKNOWN = 0,
  PROT_TRAILING,    /* unecessary trailing garbage */
  PROT_LOGICAL,     /* Logical frame */
  PROT_LINUX_SLL,
  PROT_IEEE802_3,   /* IEEE 802.3 Ethernet */
  PROT_LLC,         /* Link Layer Control */
  PROT_ARP,         /* Address Resolution Protocol */
  PROT_IPv4,
  PROT_ICMP,
  PROT_IGMPv2,
  PROT_UDP,
  PROT_BOOTP,
  PROT_SSDP,
  PROT_NBDGM,
  PROT_NBNS,
  PROT_SMB,
  PROT_BROWSE,
  PROT_TCP,
  PROT_HTTP,
  PROT_HTTPS,
  PROT_TIVOCONN,
  PROT_IPv6,
  PROT_DNS,
  PROT_SYMBOL8781,
  PROT_CDP,         /* Cisco Discovery Protocol */
  PROT_LLDP,
  PROT_RADIUS,
  PROT_STP,         /* Spanning Tree Protocol */
  PROT_IPX,
  PROT_SNMP,
  PROT_NTP,
  PROT_MCAFEE_RUMOR,
  PROT_RTSP,
  PROT_MSSQLM,
  PROT_RASADV,
  PROT_DHCPv6,
  PROT_NetBIOS,
  PROT_BITTORRENT,
  PROT_STORMBOTNET,
  PROT_GNUTELLA,
  PROT_IRC,
  PROT_WSDD,
  PROT_DCERPC,
  PROT_ESP,
#if 0
  PROT_AARP,        /* Apple Address Resolution Protocol */
  PROT_ICMPV6,
  PROT_IGMP,
  PROT_NB_SSN,
  PROT_DDP,
  PROT_SAP,         /* Service Advertisement Protocol */
  PROT_HTTPS,
  PROT_IAPP,        /* Inter-Access Point Protocol */
  PROT_LOOP,        /* Configuration Test Protocol (loopback) */
  PROT_GRE,         /* Generic Route Protocol */
  PROT_SMTP,        /* Simple Mail Transport Protocol */
  PROT_AIM,
  PROT_JABBER,
  PROT_PPP,
  PROT_TEREDO,
  PROT_CSTRIKE,
  PROT_SYMBOL_WIFI,
  PROT_CISCOWL,     /* Cisco Wireless 2 */
  PROT_FTP,
  PROT_SSH,
  PROT_TELNET,
  PROT_TFTP,
#endif
  PROT_COUNT /* total number of supported protocols */
};

/**
 * store our captured data and our attempts to parse it
 */
struct parse_status {
  char *data;         /*  */
  size_t len;         /* length of data in bytes */
  unsigned frames;    /* number of frames filled */
  struct parse_frame { /* each frame is a protocol that has been parsed */
    enum Prot id;
    size_t    len;
    void     *off,    /* pointer to raw protocol data */
             *pass;   /* optional pointer for protocol-specific data,
                         parsers can attach separate structures not
                         directly overlaid on the data here; this is necessary
                         for text-based, variable-length protocols */
  } frame[16];
};
typedef struct parse_frame parse_frame;
typedef struct parse_status parse_status;

/**
 * exported interface from protocol parsing modules
 */
struct prot_iface {
  enum Prot id;                   /* which protocol parser has claimed this data? */
  enum OSI  osi;                  /* under which layer of the OSI model are we filed?
                                   * not really used at the moment, but could be useful
                                   * in diagnosing potential issues regarding protocol
                                   * connections in the future. plus, it's informative.
                                   */
  const char * const shortname,   /* i.e. "TCP" */
             * const propername;  /* i.e. "Transmission Control Protocol" */
  /* do any protocol-specific initialization */
  int  (*init)  (void);
  void (*unload)(void);
  /* number of bytes used if valid, else 0; may write to its first parameter
   * on success modify (endianness conversion network->host) */
  size_t (*parse)(char *, size_t, parse_frame *, const parse_status *);
  size_t (*dump)(const parse_frame *, int options, FILE *);
  /* 
   * extract the 'from' and 'to' addresses, respectively, from the given parse_frame
   * and write them to the provided buffer in canonical form; if no such address
   * exists in the message return 0.
   * protocols which do not contain proper addresses (i.e. ICMP and UDP) may
   * provide NULL entries for these functions.
   * these are used for reporting traffic.
   */
  const char * const addr_type;
  const void * (*addr_from)(const parse_frame *);
  const void * (*addr_to)(const parse_frame *);
  size_t       (*addr_format)(char *buf, size_t len, const void *);
  int          (*addr_local)(const void *);
  /* how many parent protocols we test for */
  size_t parents; 
  /* candidate parent protocols and how to test for us */
  const struct prot_parent { 
    enum Prot id;
    int (*test)(const char *, size_t, const parse_status *);
  } *parent;
};
typedef struct prot_iface prot_iface;
typedef struct prot_parent prot_parent;

/**
 * 
 */
struct prot_child {
  prot_parent par;
  unsigned long cnt;  /* number of times we've been used; for move-to-front hueristic */
};
typedef struct prot_child prot_child;

/**
 * protocol module; all resources associated with a loaded library
 */
struct prot_mod {
  enum Prot id;
  const prot_iface *iface;
  size_t children; /* number of potential children */
  prot_child child[64]; /*  */
};
typedef struct prot_mod prot_mod;

#endif

