/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Remote Authentication Dial In User Service (RADIUS)
 *
 * References:
 *
 *  #1 Rigney C. RFC 2865: Remote Authentication Dial In User Service (RADIUS) [web page]
 *  June 2000 <URL: http://tools.ietf.org/rfc/rfc2865.txt> [Accessed Jan 5 2009]
 *
 *  #2 IANA PORT NUMBERS [web page]
 *  Dec 24 2008 <URL: http://www.iana.org/assignments/port-numbers> [Accessed Jan 5 2009]
 *
 *  #3 Rigney C. RFC 2866: RADIUS Accounting [web page]
 *  June 2000 <URL: http://tools.ietf.org/rfc/rfc2866.txt> [Accessed Jan 5 2009]
 *
 */

#ifndef RADIUS_H
#define RADIUS_H

#include "types.h"

/**
 * @ref #2
 */
#define RADIUS_AUTH_UDP_PORT 1812
#define RADIUS_ACCT_UDP_PORT 1813

/**
 * @ref #1 S4.1
 */
#pragma pack(push, 1)
struct radius {
  u8  code,
      id;
  u16 len;
  u8  auth[16];
  /* Attributes... */
};
#pragma pack(pop)
typedef struct radius radius;

/**
 * @ref #1 S3
 */
enum Code {
  Code_Access_Req         =  1,
  Code_Access_Accept      =  2,
  Code_Access_Reject      =  3,
  Code_Access_Acct_Req    =  4,
  Code_Access_Acct_Resp   =  5,
  Code_Access_Challenge   = 11,
  Code_Access_StatServer  = 12,
  Code_Access_StatClient  = 13
};

/**
 * @ref #1 S5
 */
#pragma pack(push, 1)
struct radius_attr {
  u8  type,
      len,
      val[1]; /* variable-length type */
};
#pragma pack(pop)
typedef struct radius_attr radius_attr;

/**
 * @ref #1 S5
 * @ref #3 S5
 */
enum Attr {
  Attr_User_Name                  =  1,
  Attr_User_Password              =  2,
  Attr_CHAP_Password              =  3,
  Attr_NAS_IP_Address             =  4,
  Attr_NAS_Port                   =  5,
  Attr_Service_Type               =  6,
  Attr_Framed_Protocol            =  7,
  Attr_Framed_IP_Address          =  8,
  Attr_Framed_IP_Netmask          =  9,
  Attr_Framed_Routing             = 10,
  Attr_Filter_Id                  = 11,
  Attr_Framed_MTU                 = 12,
  Attr_Framed_Compression         = 13,
  Attr_Login_IP_Host              = 14,
  Attr_Login_Service              = 15,
  Attr_Login_TCP_Port             = 16,
  Attr_Reply_Message              = 18,
  Attr_Callback_Number            = 19,
  Attr_Callback_Id                = 20,
  Attr_Framed_Route               = 22,
  Attr_Framed_IPX_Network         = 23,
  Attr_State                      = 24,
  Attr_Class                      = 25,
  Attr_Vendor_Specific            = 26,
  Attr_Session_Timeout            = 27,
  Attr_Idle_Timeout               = 28,
  Attr_Termination_Action         = 29,
  Attr_Called_Station_Id          = 30,
  Attr_Calling_Station_Id         = 31,
  Attr_NAS_Identifier             = 32,
  Attr_Proxy_State                = 33,
  Attr_Login_LAT_Service          = 34,
  Attr_Login_LAT_Node             = 35,
  Attr_Login_LAT_Group            = 36,
  Attr_Framed_AppleTalk_Link      = 37,
  Attr_Framed_AppleTalk_Network   = 38,
  Attr_Framed_AppleTalk_Zone      = 39,
  Attr_Acct_Status_Type           = 40,
  Attr_Acct_Delay_Time            = 41,
  Attr_Acct_Input_Octets          = 42,
  Attr_Acct_Output_Octets         = 43,
  Attr_Acct_Session_Id            = 44,
  Attr_Acct_Authentic             = 45,
  Attr_Acct_Session_Time          = 46,
  Attr_Acct_Input_Packets         = 47,
  Attr_Acct_Output_Packets        = 48,
  Attr_Acct_Terminate_Cause       = 49,
  Attr_Acct_Multi_Session_Id      = 50,
  Attr_Acct_Link_Count            = 51,
  Attr_CHAP_Challenge             = 60,
  Attr_NAS_Port_Type              = 61,
  Attr_Port_Limit                 = 62,
  Attr_Login_LAT_Port             = 63
};

#endif

