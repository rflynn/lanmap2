/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * MSSQLM - Microsoft SQL Server Monitor
 *
 * References:
 *
 *
 */

#ifndef MSSQLM_H
#define MSSQLM_H

#include "types.h"
#include "http.h" /* ptrlen struct */

#define MSSQLM_UDP_PORT 1434

#pragma pack(push, 1)
struct mssqlm {
  u8  code;
};
#pragma pack(pop)
typedef struct mssqlm mssqlm;

/**
 * Just from detective/guesswork work
 */
enum Code {
  Code_Inquire  = 0x2, /* globally broadcast */
  Code_Report   = 0x5
};

/**
 * 
 */
struct kv_list {
  unsigned cnt;
  struct kv {
    ptrlen key,
           val;
  } kv[32];
};

#endif

