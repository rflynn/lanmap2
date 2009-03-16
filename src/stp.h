/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * STP - Spanning Tree Protocol
 *
 * References:
 *
 *  #1 IEEE 802.1D
 *
 */

#ifndef STP_H
#define STP_H

#include "types.h"
#include "ieee802_3.h"

#define STP_LLC_PID 0x010b

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct stp {
  u16 protocol;
  u8  version,
      bpdu_type,
      topo_change:1,
      _:6,
      topo_change_ack:1;
  struct {
    u16                 id;
    ieee802_3_mac_addr  mac;
    u32                 path_cost;
  } root;
  struct {
    u16                 id;
    ieee802_3_mac_addr  mac;
  } bridge;
  u16 port,
      msg_age,
      msg_maxage,
      hello,
      forward;
};
#pragma pack(pop)
typedef struct stp stp;

#endif

