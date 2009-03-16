/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * UDP
 *
 * References:
 *
 *  #1 ?????????????
 *
 */

#ifndef UDP_H
#define UDP_H

#include "types.h"

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct udp {
  u16 srcport,
      dstport,
      length,
      chksum;
};
#pragma pack(pop)
typedef struct udp udp;

#endif

