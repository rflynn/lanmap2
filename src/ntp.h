/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * NTP - Network Time Protocol
 *
 * References:
 *
 *  #1 
 *
 */

#ifndef NTP_H
#define NTP_H

#include "types.h"

#define NTP_UDP_PORT  123

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct ntp {
  u8  mode:3,
      version:3,
      leap:2;
  u8  stratum,
      ppoll,
      precision;
  u32 rootdelay,
      rootdisp,
      refid;
  u8  reftime[8],
      orig[8],
      recv[8],
      transmit[8];
  u32 keyid;
  u8  auth[16];
};
#pragma pack(pop)
typedef struct ntp ntp;

/**
 * @ref #1 S"Mode"
 */
enum Mode {
  Mode_Unspec,
  Mode_SymActive,
  Mode_SymPassive,
  Mode_Client,
  Mode_Server,
  Mode_Broadcast,
  Mode_NTPCtrl,
  Mode_Private,
  Mode_COUNT /* last, special */
};

/**
 * @ref #1 
 */
enum Leap {
  Leap_NoWarn       =  0,
  Leap_LastMin61    =  1,
  Leap_LastMin59    = 10,
  Leap_AlarmUnsync  = 11
};

#endif

