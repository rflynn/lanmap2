/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * Web Service Dynamic Discovery
 *
 * An XML-based protocol delivered over UDP port 3702 by components of
 * Windows Vista to implement those annoying "Neighbor" messages, apparently.
 *
 * References:
 *
 *  #1 Beatty, John et all. "Web Services Dynamic Discovery (WS-Discovery)"
 *     April 2005 [web page]
 *     <URL: http://specs.xmlsoap.org/ws/2005/04/discovery/ws-discovery.pdf>
 *     [Accessed Jan 21 2009]
 *
 */

#ifndef WSDD_H
#define WSDD_H

#include "types.h"

/* @ref #1 S2.4 */
#define WSDD_UDP_PORT 3702

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct wsdd {
  int parse_xml_someday;
};
#pragma pack(pop)
typedef struct wsdd wsdd;

#endif

