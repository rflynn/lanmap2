/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * NetBIOS
 *
 * References:
 *
 */

#ifndef NETBIOS_H
#define NETBIOS_H

#include "types.h"

#define NETBIOS_LLC   0xf0

/**
 * 
 */
#pragma pack(push, 1)
struct netbios {
  u16 len;
  u8  delim[2],
      cmd,
      pad;
};
#pragma pack(pop)
typedef struct netbios netbios;

enum Cmd {
  Cmd_Datagram  = 0x8,
  Cmd_Query     = 0xa
};

#pragma pack(push, 1)
struct nametype {
  u8  name[15],
      type;
};
#pragma pack(pop)
typedef struct nametype nametype;

enum Type {
  Type_Workstation  = 0x00,
  Type_LocalMaster  = 0x1d
};

#pragma pack(push, 1)
struct nb_dgram {
  u8        pad[6];
  nametype  rcv,
            snd;
};
#pragma pack(pop)
typedef struct nb_dgram nb_dgram;

#pragma pack(push, 1)
struct nb_qry {
  u8        localsess,
            callernametype,
            pad[2];
  u16       respcorollate;
  nametype  who;
  char      name[16];
};
#pragma pack(pop)
typedef struct nb_qry nb_qry;

#endif

