/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * McAfee Rumor
 *
 * References:
 *
 *  #1 
 *
 */

#ifndef MCAFEE_RUMOR_H
#define MCAFEE_RUMOR_H

#include "types.h"

#define MCAFEE_RUMOR_SRC_UDP_PORT 6515
#define MCAFEE_RUMOR_DST_UDP_PORT 6514

#if 0
/*
<rumor\x20type="endrequest"\x20version="1.1"\x20rid="26"\x20href="http://vs.mcafeeasap.com/MC/ENU/VS47/bin/PALLAG.001.CAB"/>
*/
#endif

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct rumor {
  u8 tag,
     rumor[5],
     space,
     attr[1]; /* variable-length */
};
#pragma pack(pop)
typedef struct rumor rumor;

#endif

