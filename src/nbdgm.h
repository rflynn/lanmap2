/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * NetBIOS Datagram
 *
 * References:
 *
 *  #1 Network Working Group PROTOCOL STANDARD FOR A NetBIOS SERVICE ON
 *     A TCP/UDP TRANSPORT DETAILED SPECIFICATIONS [web page]
 *     <URL: http://tools.ietf.org/rfc/rfc1002.txt> [Accessed Dec 29 2008]
 *  #2 Microsoft "ASCII and Hex Representation of NetBIOS Names" [web page]
 *    <URL: http://support.microsoft.com/kb/194203> [Accessed Dec 23 2008]
 *    local: ref/ASCII-and-Hex-Representation-of-NetBIOS-Names.html
 *  #3 Hertel, Christopher R. Implementing CIFS: The Common Internet Filesystem [web page] <URL: http://ubiqx.org/cifs/NetBIOS.html> [Accessed Dec 29 2008]
 *
 */

#ifndef NBDGM_H
#define NBDGM_H

#include "types.h"

#define NBDGM_UDP_PORT 138

/**
 * memory overlay of fixed-width header
 * @ref #1 S4.4.1
 */
#pragma pack(push, 1)
struct nb_dgm {
  u8  msgtype;      /*  */
  u8  snt:6,        /* Send Node Type */
      f:1,          /* Fragmented? */
      m:1;          /* More fragments? */
  u16 id;           /*  */
  ipv4_addr srcip;  /*  */
  u16 srcport,      /*  */
      len,          /*  */
      off;          /*  */
                    /* variable-length source name */
                    /* variable-length dest name */
};
#pragma pack(pop)
typedef struct nb_dgm nb_dgm;

/**
 * @ref #1 S4.4.1
 */
enum Msgtype {
  Msgtype_Unknown       =    0, /* FIXME: 0 may very well be used... */
  Msgtype_Direct_Unique = 0x10, 
  Msgtype_Direct_Group  = 0x11, 
  Msgtype_Broadcast     = 0x12, 
  Msgtype_Error         = 0x13, 
  Msgtype_Query_Request = 0x14, 
  Msgtype_Resp_Positive = 0x15, 
  Msgtype_Resp_Negative = 0x16
};

/**
 * @ref #1 S4.4.1
 */
enum Nodetype {
  Nodetype_B     = 0,
  Nodetype_P     = 1,
  Nodetype_M     = 2,
  Nodetype_NBDD  = 3
};


/**
 * once parsed, this structure
 */
struct nb_dgm_name {
  nb_dgm *head;
  char   *srcname,
         *dstname;
  u8      srcnamelen,
          dstnamelen;
};
typedef struct nb_dgm_name nb_dgm_name;

/* exported for NB* */
size_t nb_decode_name(char *wr, size_t wrlen, const char *rd, size_t rdlen);

#endif

