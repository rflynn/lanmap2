/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * SNMP
 *
 * References:
 *
 *  #1 Case, J. RFC 1157: A Simple Network Management Protocol (SNMP)
 *     May 1990 [web page] <URL: http://tools.ietf.org/rfc/rfc1157.txt>
 *     [Accessed Jan 6 2009]
 *
 */

#ifndef SNMP_H
#define SNMP_H

#include "types.h"

#define SNMP_UDP_PORT       161
#define SNMP_TRAP_UDP_PORT  162

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct tlv {
  u8  type,
      len,
      val[1]; /* variable-length */
};
#pragma pack(pop)
typedef struct tlv tlv;

struct snmp_save {
  tlv *version,
      *community,
      *pdu;
};

enum PDU {
  GetReq,
  GetNextReq,
  GetResp,
  SetReq,
  Trap
};

enum ERR {
  NoError,
  TooBig,
  NoSuchName,
  BadValue,
  ReadOnly,
  GenError
};

#endif

