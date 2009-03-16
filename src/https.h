/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * HTTPS - Secure HTTP
 *
 * References:
 *
 *  #1 ?????????????
 *
 */

#ifndef HTTPS_H
#define HTTPS_H

#include "types.h"

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct https {
  int unused;
};
#pragma pack(pop)
typedef struct https https;

#endif

