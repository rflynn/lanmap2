/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * Internet Control Message Protocol
 *
 * Ref:
 *  #1 
 */

#ifndef ICMP_H
#define ICMP_H

#include "types.h"
#include "report.h"
#include "util.h"
#include "ipv4.h"

/**
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     <message-dependent>                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/**
 * Ref #1 p.19
 */
enum Type {
  Type_EchoReply      =  0,
  Type_DestUnreach    =  3,
  Type_SourceQuench   =  4,
  Type_Redirect       =  5,
  Type_Echo           =  8,
  Type_TimeExceed     = 11,
  Type_ParamProb      = 12,
  Type_Timestamp      = 13,
  Type_TimestampReply = 14,
  Type_InfoReq        = 15,
  Type_InfoReply      = 16,
  Type_COUNT /* last, special */
};

enum NetUnreach {
  NetUnreach_NetUnreach  = 0,
  NetUnreach_HostUnreach = 1,
  NetUnreach_ProtUnreach = 2,
  NetUnreach_PortUnreach = 3,
  NetUnreach_FragNeeded  = 4,
  NetUnreach_SourceRoute = 5
};

enum TimeExceed {
  TimeExceed_TTL  = 0,
  TimeExceed_Frag = 1,
};

enum Redirect {
  Redirect_Net     = 0,
  Redirect_Host    = 1,
  Redirect_ToSNet  = 2,
  Redirect_ToSHost = 3,
};

#pragma pack(push, 1)
struct icmp {
  struct {
    u8  type,
        code;
    u16 chksum;
  } head;
  union {
    struct {            /* Destination Unreachable
                         * Time Exceeded
                         * Source Quench */
      u32  unused;
      ipv4 hdr;
      u8   data[8];
    } unreach;
    struct {            /* Parameter Problem */
      u8   ptr,
           unused[3];
      ipv4 hdr;
      u8   data[8];
    } param;
    struct {            /* Redirect Message */
      ipv4_addr gateway;
      ipv4      hdr;
      u8        data[8];
    } redirect;
    struct {            /* Echo or Echo Reply */
      u16 id,
          seq;
      u8  payload[8];
    } echo;
    struct {            /* Timestamp or Timestamp Reply */
      u32 orig,
          recv,
          trans;
    } timestamp;
    struct {            /* Information Request or Information Reply */
      u16 id,
          seq;
    } info;
  } data;
  /* variable data, depending on code */
};
#pragma pack(pop) 
typedef struct icmp icmp;

struct permsg {
  u8                  code;
  const char         *shortname,
                     *longname;
  size_t              minbytes; /* minimum payload by code */
  const char * const *codestr;
  size_t              codestrsize;
};

#endif

