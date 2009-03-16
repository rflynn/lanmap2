/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 */

#ifndef OS_H
#define OS_H

#include "types.h"

/* 
 * os.csv format currently defined as:
 *  #Id,Name,Parent,Comment
 */
struct os {
  char id[24],
       name[32];
  s32  weight;
};
typedef struct os os;

#endif

