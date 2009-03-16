/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Symbol 0x8781
 *
 * References:
 *
 */

#ifndef SYMBOL8781_H
#define SYMBOL8781_H

#include "types.h"
#include "ipv4.h"

#if 0
/*
0000   01:a0:f8:f0:f0:02 00:a0:f8:37:a5:ae 87 81 00 2d  .........7.....-
0010   08 00 00 76 00 00 00 06 00 07 00 00 00 01 0a 2c  ...v...........,
0020   16 b5 00 00 00 00 09 2b 00 00 00 00 02 03 03 00  .......+........
0030   00 00 00 00 00 01 54 45 53 54 00 00 00 00 00 00  ......TEST......
0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0050   00 00 00 00 00 00 00 00 00 00 00 0a 30 34 2e 30  ............04.0
0060   32 2d 31 39 00 00 00 00 00 00 00 00 45 6e 67 69  2-19........Engi
0070   6e 65 65 72 69 6e 67 20 4c 61 62 2c 20 54 45 53  neering Lab, TES
0080   54 00 00 00 00 00 00 00 00 00 00 00              T...........
*/

#endif

/**
 *
 */
#pragma pack(push, 1)
struct symbol8781 {
  s8        u0[16];
  ipv4_addr ip;
  s8        u1[20];
  s8        name[38],
            date[16],
            namelong[32];
};
#pragma pack(pop)
typedef struct symbol8781 symbol8781;

#endif

