/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * 
 */

#ifndef ENC_H
#define ENC_H

/**
 * Designated INITializer from C99, if we have it.
 * Helpful in catching bugs in large structure initializations.
 */
#if (defined(__cplusplus) || defined(__STD_C__) || defined(__GNUC__))
# define DINIT(field, val)  .field = val
#else
# define DINIT(field, val)  val
#endif

#if defined(__LITTLE_ENDIAN__)
# define IS_BIG_ENDIAN    0
# define IS_LITTLE_ENDIAN 1
#elif defined(__BIG_ENDIAN__)
# define IS_BIG_ENDIAN    1
# define IS_LITTLE_ENDIAN 0
#else
# error fix endianness detection!
#endif

#endif

