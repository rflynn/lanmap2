/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * ESP - Encapsulating Security Payload
 *
 * References:
 *
 *  #1 ?????????????
 *
 */

#ifndef ESP_H
#define ESP_H

#include "types.h"

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct esp {
  u32 spi,
      seq;
};
#pragma pack(pop)
typedef struct esp esp;

#endif

