/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Convenient aliases for exact-width integer types
 */

#ifndef INT_ALIAS_H
#define INT_ALIAS_H

#include <stdint.h>

typedef   int8_t  s8;
typedef  uint8_t  u8;
typedef  int16_t s16;
typedef uint16_t u16;
typedef  int32_t s32;
typedef uint32_t u32;
typedef  int64_t s64;
typedef uint64_t u64;

struct ptrlen {
  char *start;
  unsigned len;
};
typedef struct ptrlen ptrlen;

struct ptrlen_list {
  unsigned cnt;
  ptrlen p[8];
};
typedef struct ptrlen_list ptrlen_list;

/*
 * detect native endianness. assume little unless explicitly otherwise.
 */
#if defined(__BIG_ENDIAN__) || defined(__BIG_ENDIAN)
# define LANMAP2_BIG_ENDIAN
#else
# define LANMAP2_LITTLE_ENDIAN
#endif

#endif

