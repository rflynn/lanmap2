/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Real Time Streaming Protocol (RTSP)
 *
 * Ref:
 *  #1 Schulzrinne, H. RFC 2326: Real Time Streaming Protocol (RTSP) [web page]
 *    April 1998 <URL: http://www.ietf.org/rfc/rfc2326.txt> [Accessed Jan 8 2009]
 *  #2 IANA RESERVED PORT NUMBERS
 *
 */

#ifndef RTSP_H
#define RTSP_H

#include "types.h"
#include "http.h"

/**
 * @ref #2
 */
#define RTSP_UDP_PORT      554
#define RTSP_TCP_PORT      554
#define RTSP_UDP_PORT_ALT 8554
#define RTSP_TCP_PORT_ALT 8554

/**
 * @ref #1 S6.1
 */
enum RTSP_Method {
  RTSP_Method_None,
  RTSP_Method_DESCRIBE,
  RTSP_Method_ANNOUNCE,
  RTSP_Method_GET_PARAMETER,
  RTSP_Method_OPTIONS,
  RTSP_Method_PAUSE,
  RTSP_Method_PLAY,
  RTSP_Method_RECORD,
  RTSP_Method_REDIRECT,
  RTSP_Method_SETUP,
  RTSP_Method_SET_PARAMETER,
  RTSP_Method_Other, /* extension-method */
  RTSP_Method_Count
};

struct rtsp {
  enum RTSP_Method method;
  http h;
};
typedef struct rtsp rtsp;

int rtsp_is_tcp_port(u16 port);
int rtsp_is_udp_port(u16 port);

#endif

