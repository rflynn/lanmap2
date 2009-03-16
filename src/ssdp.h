/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * SSDP - Simple Service Discovery Protocol
 *
 * Ref:
 *  #1 Goland, Yaron Y. IETF INTERNET DRAFT Simple Service Discovery Protocol/1.0 [web page]
 *    <URL: http://quimby.gnus.org/internet-drafts/draft-cai-ssdp-v1-03.txt>
 *    [Accessed 23 Dec 2008]
 *  #2 IANA RESERVED PORT NUMBERS
 *
 */

#ifndef SSDP_H
#define SSDP_H

#include "types.h"
#include "http.h"

/**
 * @ref #2
 */
#define SSDP_UDP_PORT   1900
#define SSDP_TCP_PORT   1900

/**
 * 
 */
enum SSDP_Method {
  SSDP_Method_None,
  SSDP_Method_NOTIFY,
  SSDP_Method_MSEARCH,
  SSDP_Method_Count
};

struct ssdp {
  enum SSDP_Method method;
  http h;
};
typedef struct ssdp ssdp;

#endif

