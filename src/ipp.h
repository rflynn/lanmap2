/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2010 Ryan Flynn
 * All rights reserved.
 */
/*
 * IPP - Internet Printing Protocol
 *
 * References:
 *
 *  #1 "RFC 2911: Internet Printing Protocol/1.1: Model and Semantics" T. Hastings <URL:http://tools.ietf.org/html/rfc2911>
 *
 */

#ifndef IPP_H
#define IPP_H

#include "types.h"

#define IPP_UDP_PORT  631

/*
 +----------------------------+---------------------------+-----------+
  |      Attribute             |     Syntax                | REQUIRED? |
  +----------------------------+---------------------------+-----------+
  | printer-uri-supported      | 1setOf uri                |  REQUIRED |
  +----------------------------+---------------------------+-----------+
  | uri-security-supported     | 1setOf type2 keyword      |  REQUIRED |
  +----------------------------+---------------------------+-----------+
  | uri-authentication-        | 1setOf type2 keyword      |  REQUIRED |
  |     supported              |                           |           |
  +----------------------------+---------------------------+-----------+
  | printer-name               | name (127)                |  REQUIRED |
  +----------------------------+---------------------------+-----------+
  | printer-location           | text (127)                |           |
  +----------------------------+---------------------------+-----------+
  | printer-info               | text (127)                |           |
  +----------------------------+---------------------------+-----------+
  | printer-more-info          | uri                       |           |
  +----------------------------+---------------------------+-----------+
  | printer-driver-installer   | uri                       |           |
  +----------------------------+---------------------------+-----------+
  | printer-make-and-model     | text (127)                |           |
  +----------------------------+---------------------------+-----------+
  | printer-more-info-         | uri                       |           |
  | manufacturer               |                           |           |
  +----------------------------+---------------------------+-----------+
  | printer-state              | type1 enum                |  REQUIRED |
  ...
*/

/**
 * @ref #1 
 */
struct ipp {
  ptrlen type,
         state,
         uri,
         loc,
         info,
         make,
         extra;
};
typedef struct ipp ipp;

#endif

