/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Logical capture from libpcap
 */
#ifndef LOGICAL_H
#define LOGICAL_H

#include "types.h"

/**
 * a logical frame adapted directly from the
 * libpcap output. this is where all packets
 * begin.
 */
struct logical_frame {
  s32     type;
  u32     bytes,
          id;
  time_t  when;
};
typedef struct logical_frame logical_frame;

#endif

