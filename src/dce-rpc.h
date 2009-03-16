/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * DCE RPC - Distributed Computing Environment Remote Procedure Call
 *
 * References:
 *
 *  #1 
 *
 */

#ifndef DCE_RPC_H
#define DCE_RPC_H

#include "types.h"

#define MSRPC_TCP_PORT 1163

/**
 * @ref ?
 */
#pragma pack(push, 1)
struct dcerpc_hdr {
  u8  maj,
      min,
      type;
};
#pragma pack(pop)
typedef struct dcerpc_hdr dcerpc_hdr;

enum Type {
  Type_Req  = 0,
  Type_Resp = 2
};

/**
 * @ref ?
 */
#pragma pack(push, 1)
struct dcerpc_flags {
  u8  first:1,
      last:1,
      cancel:1,
      res:1,
      multiplex:1,
      didnotexec:1,
      maybe:1,
      object:1;
};
#pragma pack(pop)
typedef struct dcerpc_flags dcerpc_flags;

/**
 * @ref ?
 */
#pragma pack(push, 1)
struct dcerpc_drep {
  u32 TODO;
};
#pragma pack(pop)
typedef struct dcerpc_drep dcerpc_drep;

/**
 * @ref ?
 */
#pragma pack(push, 1)
struct dcerpc_req {
  dcerpc_flags flags;
  dcerpc_drep  drep;
  u16          fraglen,
               authlen;
  u32          callid,
               alloc_hint;
  u16          contextid,
               opnum;
  u8           data[1]; /* variable-length */
};
#pragma pack(pop)
typedef struct dcerpc_req dcerpc_req;

/**
 * @ref ?
 */
#pragma pack(push, 1)
struct dcerpc_resp {
  dcerpc_flags flags;
  dcerpc_drep  drep;
  u16          fraglen,
               authlen;
  u32          callid,
               alloc_hint;
  u16          contextid,
               opnum;
  u8           cancelcnt,
               pad;
  u8           data[1]; /* variable-length */
};
#pragma pack(pop)
typedef struct dcerpc_resp dcerpc_resp;

#endif

