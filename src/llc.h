/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * LLC
 *
 * References:
 *
 *  #1 IEEE. IEEE Std 802.2, 1998 Edition(R2003) Part 2: Logical Link Control
 *    <URL: http://standards.ieee.org/getieee802/download/802.2-1998.pdf>
 *    [Accessed Jan 9 2009]
 *  #2 Wikipedia. IEEE 802.2 [web page]
 *    <URL: http://en.wikipedia.org/wiki/IEEE_802.2> [Accessed Dec 23 3008]
 *
 */

#ifndef LLC_H
#define LLC_H

#include "types.h"

#define LLC_SNAP            0xAA  /* Subnetwork Access Protocol (SNAP) */
#define LLC_DSAP_ST_BDPU    0x42
#define LLC_DSAP_NETWARE    0xE0

#define LLC_PID_CISCOWL     0x0000
#define LLC_PID_CDP         0x2000
#define LLC_PID_APPLETALK   0x809B
#define LLC_PID_AARP        0x80F3

enum {
  CTRL_XID = 0x2B
};

/**
 * @ref #1
 */
#pragma pack(push, 1)
struct llc {
  union {
    u8  all;
    u8  addr:7,
        ig:1;
  } dsap;             /* DSAP (Destination Service Access Point) */
  union {
    u8  all;
    u8  addr:7,
        cr:1;
  } ssap;             /* SSAP (Source Service Access Point) */
  /**
   * @ref #1 S5.2
   */
  union {
    u8  cmd;
    struct {
      u8  zero:1,
          sendseq:7;
      u8  pf:1,
          nr:7;
    } i;
    struct {
      u8  ten:2,
          s:2,
          x:4;
      u8  pf:1,
          nr:7;
    } s;
    struct {
      u8  eleven:2,
          m2:2,
          pf:1,
          m3:3;
    } u;
  } ctrl;
};
#pragma pack(pop)
typedef struct llc llc;

#pragma pack(push, 1)
struct llc_pid {
  u8  org[3];
  u16 pid;
};
#pragma pack(pop)
typedef struct llc_pid llc_pid;

llc_pid * llc_getpid(const llc *);

#endif

