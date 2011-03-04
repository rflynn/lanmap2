/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * TivoConnect Discovery Protocol
 *
 * References:
 *
 *  #1 Tivo, Inc. "Tivo Connect Automatic Machine Discovery Protocol Specification" Rev.151 [web page] <URL: http://dynamic.tivo.com/developer/i/TiVoConnectDiscovery.pdf> [Accessed Dec 22 2008]
 *
 */

#ifndef TIVOCONNECT_H
#define TIVOCONNECT_H

#include "types.h"

/**
 * Ref #1 S 3.1.1
 */
#pragma pack(push, 1)
struct tivoconn {
  s8  tivoconnect[11],
      eq[1];
};
#pragma pack(pop)
typedef struct tivoconn tivoconn;

enum Key {
  Key_Unknown, /* unrecognized */
  Key_Identity,
  Key_Machine,
  Key_Method,
  Key_Platform,
  Key_Services,
  Key_TiVoConn,
  Key_COUNT/* last, special */
};

#if 0
/*
TiVoConnect=1
Machine=IAPETUS
Identity={1F8EEE0B-BF38-4D25-808D-F3DA02422313}
Method=Broadcast
Platform=pc/WinNT:6.0.6001
Services=TiVoMediaServer:8080/http

tivoconnect=1
method=broadcast
platform=pc/win-nt
machine=FREDS-PC
identity={D936E980-79E3-11D6-A84A-00045A43EEE7}
services=FooService:1234,BarService:4321
*/
#endif

struct kkv {
  enum Key key;
  ptrlen  keystr,
          val;
};
typedef struct kkv kkv;

struct tivoconn_kv {
  unsigned cnt;
  kkv item[8];
};
typedef struct tivoconn_kv tivoconn_kv;

#endif

