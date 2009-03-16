/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Server Message Block
 *
 * References:
 *
 *  No proper ones; just sniffing over the wire.
 *
 */

#ifndef SMB_H
#define SMB_H

#include "types.h"

/**
 *
 */
#pragma pack(push, 1)
struct smb_hdr {
  u32 server_component;
  u8  cmd,
      err,
      res_;
  u8  errcode[2];
  u8  lckrd:1,
      rcvbufpst:1,
      casesens:1,
      res__:1,
      canonpath:1,
      oplck:1,
      notify:1,
      reqresp:1;
  u16 /* FIXME: check that this gets aligned tightly */
      longnameallow:1,  /* Long Names allowed */
      extattr:1,        /* Extended Attributes */
      secsig:1,         /* Security Signatures */
      res___:3,         /*  */
      longnameused:1,   /*  */
      res____:4,        /*  */
      extsecneg:1,      /* Extended Security Negotiation */
      dfs:1,            /*  */
      execonlyrd:1,     /*  */
      doserr:1,         /*  */
      unicode:1;        /*  */
  u16 pidhi;
  u8  sig[8];
  u16 res______,
      treeid,
      procid,
      userid,
      multiplexid;
};
#pragma pack(pop)
typedef struct smb_hdr smb_hdr;

/**
 *
 */
enum SMB_Cmd {
  SMB_Cmd_TransReq = 0x25
};

#pragma pack(push, 1)
struct smb_trans_req {
  u8  wct;
  u16 totalparam,
      totaldata,
      maxparam,
      maxdata;
  u8  maxsetup,
      res_;
  u16 discontid:1,
      onewaytrans:1,
      res__:14;
  u32 timeout;
  u16 res___,
      param,
      paramoffset,
      data,
      dataoffset;
  u8  setupcnt,
      res_____;
  struct smb_mailslot {
    u16 opcode,
        priority,
        class_,
        bytes;
  } mailslot;
  s8  name[1]; /* variable-length */
};
#pragma pack(pop)
typedef struct smb_trans_req smb_trans_req;
typedef struct smb_mailslot smb_mailslot;

#endif

