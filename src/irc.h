/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * IRC - Internet Relay Chat
 *
 * References:
 *
 *  #1 
 *
 */

#ifndef IRC_H
#define IRC_H

#include "types.h"

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct irc {
  int unused;
};
#pragma pack(pop)
typedef struct irc irc;

#endif

