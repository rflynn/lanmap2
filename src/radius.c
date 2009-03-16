/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * RADIUS
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "ipv4.h"
#include "udp.h"
#include "radius.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_udp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_UDP, test_udp }
};

/**
 * exported interface
 */
const prot_iface Iface_RADIUS = {
  DINIT(id,           PROT_RADIUS),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "RADIUS"),
  DINIT(propername,   "Remote Authentication Dial In User Service"),
  DINIT(init,         NULL),
  DINIT(unload,       NULL),
  DINIT(parse,        parse),
  DINIT(dump,         dump),
  DINIT(addr_type,    NULL),
  DINIT(addr_from,    NULL),
  DINIT(addr_to,      NULL),
  DINIT(addr_format,  NULL),
  DINIT(addr_local,   NULL),
  DINIT(parents,      sizeof Test / sizeof Test[0]),
  DINIT(parent,       Test)
};

static int test_udp(const char *buf, size_t len, const parse_status *st)
{
  const udp *u = (udp *)st->frame[st->frames-1].off;
  return len > sizeof(radius) &&
     ( RADIUS_AUTH_UDP_PORT == u->srcport
    || RADIUS_AUTH_UDP_PORT == u->dstport
    || RADIUS_ACCT_UDP_PORT == u->srcport
    || RADIUS_ACCT_UDP_PORT == u->dstport);
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  radius *r = (radius *)buf;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *r > len)
    return 0;
  /* convert endianness */
  r->len = ntohs(r->len);
  bytes = len;
  return bytes; 
}

typedef struct code_struct code_struct;
static const struct code_struct {
  enum Code code;
  const char *name;
} ByCode[] = {
  { 0,                      "(0)"           },
  { Code_Access_Req,        "Access-Req"    },
  { Code_Access_Accept,     "Access-Accept" },
  { Code_Access_Reject,     "Access-Reject" },
  { Code_Access_Acct_Req,   "Acct-Req"      },
  { Code_Access_Acct_Resp,  "Acct-Resp"     }
};

typedef struct attr_struct attr_struct;
static const struct attr_struct {
  enum Attr attr;
  const char *name;
  int is_string;
  size_t (*parse)(char *, size_t, const parse_status *);
} ByAttr[] = {
  { 0,                              "(0)",                        0, NULL },
  { Attr_User_Name,                 "User_Name",                  0, NULL },
  { Attr_User_Password,             "User_Password",              0, NULL },
  { Attr_CHAP_Password,             "CHAP_Password",              0, NULL },
  { Attr_NAS_IP_Address,            "NAS_IP_Address",             0, NULL },
  { Attr_NAS_Port,                  "NAS_Port",                   0, NULL },
  { Attr_Service_Type,              "Service_Type",               0, NULL },
  { Attr_Framed_Protocol,           "Framed_Protocol",            0, NULL },
  { Attr_Framed_IP_Address,         "Framed_IP_Address",          0, NULL },
  { Attr_Framed_IP_Netmask,         "Framed_IP_Netmask",          0, NULL },
  { Attr_Framed_Routing,            "Framed_Routing",             0, NULL },
  { Attr_Filter_Id,                 "Filter_Id",                  0, NULL },
  { Attr_Framed_MTU,                "Framed_MTU",                 0, NULL },
  { Attr_Framed_Compression,        "Framed_Compression",         0, NULL },
  { Attr_Login_IP_Host,             "Login_IP_Host",              0, NULL },
  { Attr_Login_Service,             "Login_Service",              0, NULL },
  { Attr_Login_TCP_Port,            "Login_TCP_Port",             0, NULL },
  { 17,                             "(17)",                       0, NULL },
  { Attr_Reply_Message,             "Reply_Message",              0, NULL },
  { Attr_Callback_Number,           "Callback_Number",            0, NULL },
  { Attr_Callback_Id,               "Callback_Id",                0, NULL },
  { 21,                             "(21)",                       0, NULL },
  { Attr_Framed_Route,              "Framed_Route",               0, NULL },
  { Attr_Framed_IPX_Network,        "Framed_IPX_Network",         0, NULL },
  { Attr_State,                     "State",                      0, NULL },
  { Attr_Class,                     "Class",                      0, NULL },
  { Attr_Vendor_Specific,           "Vendor_Specific",            0, NULL },
  { Attr_Session_Timeout,           "Session_Timeout",            0, NULL },
  { Attr_Idle_Timeout,              "Idle_Timeout",               0, NULL },
  { Attr_Termination_Action,        "Termination_Action",         0, NULL },
  { Attr_Called_Station_Id,         "Called_Station_Id",          0, NULL },
  { Attr_Calling_Station_Id,        "Calling_Station_Id",         0, NULL },
  { Attr_NAS_Identifier,            "NAS_Identifier",             0, NULL },
  { Attr_Proxy_State,               "Proxy_State",                0, NULL },
  { Attr_Login_LAT_Service,         "Login_LAT_Service",          0, NULL },
  { Attr_Login_LAT_Node,            "Login_LAT_Node",             0, NULL },
  { Attr_Login_LAT_Group,           "Login_LAT_Group",            0, NULL },
  { Attr_Framed_AppleTalk_Link,     "Framed_AppleTalk_Link",      0, NULL },
  { Attr_Framed_AppleTalk_Network,  "Framed-AppleTalk-Network",   0, NULL },
  { Attr_Framed_AppleTalk_Zone,     "Framed_AppleTalk_Zone",      0, NULL },
  { Attr_Acct_Status_Type,          "Acct_Status_Type",           0, NULL },
  { Attr_Acct_Delay_Time,           "Acct_Delay_Time",            0, NULL },
  { Attr_Acct_Input_Octets,         "Acct_Input_Octets",          0, NULL },
  { Attr_Acct_Output_Octets,        "Acct_Output_Octets",         0, NULL },
  { Attr_Acct_Session_Id,           "Acct_Session_Id",            0, NULL },
  { Attr_Acct_Authentic,            "Acct_Authentic",             0, NULL },
  { Attr_Acct_Session_Time,         "Acct_Session_Time",          0, NULL },
  { Attr_Acct_Input_Packets,        "Acct_Input_Packets",         0, NULL },
  { Attr_Acct_Output_Packets,       "Acct_Output_Packets",        0, NULL },
  { Attr_Acct_Terminate_Cause,      "Acct_Terminate_Cause",       0, NULL },
  { Attr_Acct_Multi_Session_Id,     "Acct_Multi_Session_Id",      0, NULL },
  { Attr_Acct_Link_Count,           "Acct_Link_Count",            0, NULL },
  { 52,                             "(52)",                       0, NULL },
  { 53,                             "(53)",                       0, NULL },
  { 54,                             "(54)",                       0, NULL },
  { 55,                             "(55)",                       0, NULL },
  { 56,                             "(56)",                       0, NULL },
  { 57,                             "(57)",                       0, NULL },
  { 58,                             "(58)",                       0, NULL },
  { 59,                             "(59)",                       0, NULL },
  { Attr_CHAP_Challenge,            "CHAP_Challenge",             0, NULL },
  { Attr_NAS_Port_Type,             "NAS_Port_Type",              0, NULL },
  { Attr_Port_Limit,                "Port_Limit",                 0, NULL },
  { Attr_Login_LAT_Port,            "Login_LAT_Port",             0, NULL }
};

static const char * code2name(u8 code)
{
  const char *s = "?";
  if (code < sizeof ByCode / sizeof ByCode[0])
    s = ByCode[code].name;
  return s;
}

static const attr_struct * attr2struct(u8 type)
{
  const struct attr_struct *a = NULL;
  if (type < sizeof ByAttr / sizeof ByAttr[0])
    a = ByAttr + type;
  return a;
}

static size_t dump_attrs(const radius *r, const char *buf, size_t len, FILE *out)
{
  int bytes = 0;
  if (r->len < len)
    len = r->len;
  while (len) {
    const radius_attr *a = (radius_attr *)buf;
    const attr_struct *s;
    if (a->len < 3 || a->len > len)
      break;
    s = attr2struct(a->type);
    bytes += fprintf(out, "  #%2u %-20s ", a->type, s ? s->name : "?");
    bytes += dump_chars((char *)a->val, a->len-2, out);
    fputc('\n', stdout);
    bytes++;
    buf += a->len;
    len -= a->len;
  }
  return (size_t)bytes;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  char authbuf[64+1];
  const char *buf = f->off;
  const radius *r = (radius *)buf;
  int bytes;
  dump_bytes_buf(authbuf, sizeof authbuf, (char *)r->auth, sizeof r->auth);
  bytes = fprintf(out,
    "%s "
    "code=%u(%s) id=0x%x len=%hu auth=%s\n",
    Iface_RADIUS.shortname,
    r->code, code2name(r->code), r->id, r->len, authbuf);
  bytes += dump_attrs(r, buf + sizeof *r, f->len - sizeof *r, out);
  return (size_t)bytes;
}

static void sanity_check(void)
{
  unsigned i;
  assert(20 == sizeof(radius));
  assert(3 == sizeof(radius_attr));
  for (i = 0; i < sizeof ByCode / sizeof ByCode[0]; i++)
    assert(ByCode[i].code == i);
  for (i = 0; i < sizeof ByAttr / sizeof ByAttr[0]; i++)
    assert(ByAttr[i].attr == i);
}

static int init(void)
{
  sanity_check();
  return 1;
}

#ifdef TEST

static char Sample[172] = "\x04\x8f\x00\xac\x5c\xea\xec\x51\xa9\xd2\xee\x08\x52\x12\xa0\x08\x47\x47\xcf\x31\x01\x0e\x30\x30\x30\x35\x34\x65\x34\x35\x66\x35\x62\x31\x05\x06\x00\x00\x00\x04\x04\x06\x0a\x2b\x6e\x32\x20\x09\x43\x50\x43\x33\x30\x30\x30\x1a\x0c\x00\x00\x37\x63\x01\x06\x00\x00\x00\x05\x2c\x1e\x34\x39\x33\x62\x63\x62\x62\x65\x2f\x30\x30\x3a\x30\x35\x3a\x34\x65\x3a\x34\x35\x3a\x66\x35\x3a\x62\x31\x2f\x30\x2d\x06\x00\x00\x00\x03\x28\x06\x00\x00\x00\x03\x2a\x06\x07\x46\xa0\x47\x2b\x06\x04\x95\x14\xdc\x2f\x06\x00\x3a\x1a\x4d\x30\x06\x00\x01\x67\xbb\x2e\x06\x00\x26\x45\xd7\x29\x06\x00\x00\x00\x00\x1f\x0d\x31\x30\x2e\x34\x33\x2e\x39\x37\x2e\x32\x37\x1e\x0e\x31\x30\x2e\x34\x33\x2e\x31\x31\x30\x2e\x35\x30";

static void test(void)
{
  parse_frame pf = { PROT_RADIUS, sizeof Sample, Sample, NULL };
  init();
  parse(pf.off, pf.len, &pf, NULL);
  dump(&pf, 0, stdout);
}

int main(void)
{
  test();
  return 0;
}
#endif

