/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Transmission Control Protocol
 *
 * Ref:
 *  #1 Information Sciences Institute RFC 793 "TRANSMISSION CONTROL PROTOCOL" Sep 1981 [web page]
 *     <URL: http://www.ietf.org/rfc/rfc793.txt> [Accessed Dec 1 2008]
 *  #2 IANA "Transmission Control Protocol (TCP) Option Numbers" 2007-02-15 [web page]
 *     <URL: http://www.iana.org/assignments/tcp-parameters/> [Accessed Jan 13 2009]
 */

#ifndef TCP_H
#define TCP_H

#include "types.h"

#define TCP_OFF_MIN            5  /* Ref #1 */
#define TCP_OFF_MAX           15

/**
 * @ref #2
 */
enum TCP_Opt {
  TCP_Opt_End         =  0, /* @ref #1 */
  TCP_Opt_NOP         =  1, /* @ref #1 */
  TCP_Opt_MSS         =  2, /* @ref #1 */
  TCP_Opt_WSOPT       =  3,
  TCP_Opt_SACKPerm    =  4,
  TCP_Opt_SACK        =  5,
  TCP_Opt_Echo        =  6,
  TCP_Opt_EchoReply   =  7,
  TCP_Opt_TSOPT       =  8,
  TCP_Opt_POCP        =  9,
  TCP_Opt_POSP        = 10,
  TCP_Opt_CC          = 11,
  TCP_Opt_CCNEW       = 12,
  TCP_Opt_CCECHO      = 13,
  TCP_Opt_AltChkReq   = 14,
  TCP_Opt_AltChkData  = 15,
  TCP_Opt_Skeeter     = 16,
  TCP_Opt_Bubba       = 17,
  TCP_Opt_TrailChksum = 18,
  TCP_Opt_MD5Sig      = 19,
  TCP_Opt_SCPS        = 20,
  TCP_Opt_SNA         = 21,
  TCP_Opt_RecBound    = 22,
  TCP_Opt_Corruption  = 23,
  TCP_Opt_SNAP        = 24,
  TCP_Opt_CompFilt    = 26,
  TCP_Opt_QuickStart  = 27
};

/**
 * TCP - Transmission Control Protocol
  
  TCP Header Format
  
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#pragma pack(push, 1)
struct tcp {
  u16       srcport,
            dstport;
  u32       seqno,
            ackno;
  u16       reserved:4,
            off:4,
            fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ecn:1,
            cwr:1;
  u16       window,
            chksum,
            urgptr;
  u8        opt[4]; /* Variable-length option field */
};
#pragma pack(pop)
typedef struct tcp tcp;

/**
 * all options are in the format of a TLV (type, length, value) structure
 */
#pragma pack(push, 1)
struct tcp_opt {
  u8 type,
     len,
     val[1]; /* variable-length data */
};
#pragma pack(pop)
typedef struct tcp_opt tcp_opt;

#pragma pack(push, 1)
struct tcp_opt_wss {
  u16 wss;
};
#pragma pack(pop)
typedef struct tcp_opt_wss tcp_opt_wss;

#pragma pack(push, 1)
struct tcp_opt_ts {
  u8 val[8];
};
#pragma pack(pop)
typedef struct tcp_opt_ts tcp_opt_ts;

#pragma pack(push, 1)
struct tcp_opt_win {
  u8 scale;
};
#pragma pack(pop)
typedef struct tcp_opt_win tcp_opt_win;

#endif

