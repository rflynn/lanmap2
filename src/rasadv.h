/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * RASADV - RAS/RRAS Routing and Remote Access Server advertisement by Windows 2000, Windows XP and Windows Server 2003 servers
 *
 * References:
 *  #1 McFarlane, Alan J. "On 235.255.2.2 9753 rasadv" [web page]
 *     <URL: http://www.alanjmcf.me.uk/comms/ip/misc/239.255.2.2%209753%20rasadv.html>
 *     [Accessed 12 Jan 2009]
 *
 */

#ifndef RASADV_H
#define RASADV_H

#include "types.h"
#include "http.h" /* ptrlen struct */

#define RASADV_UDP_PORT 9753

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

