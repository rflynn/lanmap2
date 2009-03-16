/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * IPX
 *
 * References:
 *
 *  #1 SCO "IPX header fields" [web page]
 *     <URL: http://docsrv.sco.com/SDK_netware/IPX_Header_Fields.html>
 *     [Accessed 11 Jan 2008]
 *
 */

#ifndef IPX_H
#define IPX_H

#include "types.h"
#include "ieee802_3.h"

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct ipx {
  u16 chksum,
      pktlen;
  u8  hops,
      type;
  struct {
    u32                 net;
    ieee802_3_mac_addr  m;
    u16                 socket;
  } dst, src;
};
#pragma pack(pop)
typedef struct ipx ipx;

enum IPX_Type {
  IPX_Type_RIP        = 0x01,
  IPX_Type_Echo       = 0x02,
  IPX_Type_Error      = 0x03,
  IPX_Type_PEP        = 0x04,
  IPX_Type_SPX        = 0x05,
  IPX_Type_NCP        = 0x11,
  IPX_Type_NB_Bcast   = 0x14
};

enum IPX_Socket {
  IPX_Socket_RIP      = 0x0001,
  IPX_Socket_Echo     = 0x0002,
  IPX_Socket_Error    = 0x0003,
  IPX_Socket_NVT      = 0x0247,
  IPX_Socket_NCP      = 0x0451,
  IPX_Socket_SAP      = 0x0452,
  IPX_Socket_RIP2     = 0x0453,
  IPX_Socket_NetBIOS  = 0x0455,
  IPX_Socket_Diag     = 0x0456,
  IPX_Socket_Serial   = 0x0457,
  IPX_Socket_IPX      = 0x8060,
  IPX_Socket_NVT2     = 0x8063,
  IPX_Socket_PrintServ= 0x811E,
  IPX_Socket_TCP_IPXF = 0x9091,
  IPX_Socket_UDP_IPXF = 0x9092,
  IPX_Socket_IPXF     = 0x9093,
  IPX_Socket_Dynamic  = 0x0bb9
};

#endif

