/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * HTTP - HyperText Transfer Protocol
 *
 * Ref:
 *  #1 RFC 2616 "Hypertext Transfer Protocol -- HTTP/1.1" [web page]
 *    <URL: http://tools.ietf.org/rfc/rfc2616.txt> [Accessed 18 Dec 2008]
 *  #2 RFC 2183 "The Content-Disposition Header Field" [web page]
 *    <URL: http://tools.ietf.org/rfc/rfc2183.txt> [Accessed 18 Dec 2008]
 *  #3 IANA RESERVED PORT NUMBERS
 */
/*
 * Note: http.h is used in other protocols, so our enums and
 * types must be prefixed with HTTP_/http_ so as to avoid
 * namespace collisions
 */

#ifndef HTTP_H
#define HTTP_H

#include "types.h"

/**
 * @ref #3
 */
#define HTTP_UDP_PORT         80
#define HTTP_TCP_PORT         80
#define HTTP_SCTP_PORT        80
#define HTTP_UDP_PORT_ALT   8008
#define HTTP_TCP_PORT_ALT   8008
#define HTTP_UDP_PORT_ALT2  8080
#define HTTP_TCP_PORT_ALT2  8080

/**
 * @ref #1 p.35
 */
enum HTTP_Method {
  HTTP_Method_None,
  HTTP_Method_OPTIONS,
  HTTP_Method_GET,
  HTTP_Method_HEAD,
  HTTP_Method_POST,
  HTTP_Method_PUT,
  HTTP_Method_DELETE,
  HTTP_Method_TRACE,
  HTTP_Method_CONNECT,
  HTTP_Method_Extension,
};

/**
 * Ref #1 S6.1.1 p.38-39
 */
enum HTTP_Code_Type {
  HTTP_Code_Type_None,
  HTTP_Code_Type_Info,       /* Informational */
  HTTP_Code_Type_Success,    /* Success */
  HTTP_Code_Type_Redir,      /* Redirection */
  HTTP_Code_Type_CliErr,     /* Client Error */
  HTTP_Code_Type_ServErr,    /* Server Error */
  HTTP_Code_Type_COUNT
};

enum HTTP_Code {
  HTTP_Code_None,
  HTTP_Code_Continue,
  HTTP_Code_SwitchProt,
  HTTP_Code_OK,
  HTTP_Code_Created,
  HTTP_Code_Accepted,
  HTTP_Code_NonAuthInfo,
  HTTP_Code_NoContent,
  HTTP_Code_ResetContent,
  HTTP_Code_PartContent,
  HTTP_Code_MultChoice,
  HTTP_Code_MovedPerm,
  HTTP_Code_Found,
  HTTP_Code_SeeOther,
  HTTP_Code_NotMod,
  HTTP_Code_UseProxy,
  HTTP_Code_TempRedir,
  HTTP_Code_BadReq,
  HTTP_Code_Unauth,
  HTTP_Code_PayReq,
  HTTP_Code_Forbid,
  HTTP_Code_NotFound,
  HTTP_Code_MethodNotAllow,
  HTTP_Code_NotAcc,
  HTTP_Code_ProxyAuthReq,
  HTTP_Code_ReqTimeout,
  HTTP_Code_Conflict,
  HTTP_Code_Gone,
  HTTP_Code_LenReq,
  HTTP_Code_PrecFail,
  HTTP_Code_ReqEntTooLarge,
  HTTP_Code_ReqURITooLarge,
  HTTP_Code_UnsupMediaType,
  HTTP_Code_ReqRangeBad,
  HTTP_Code_ExpectFail,
  HTTP_Code_IntServErr,
  HTTP_Code_NotImp,
  HTTP_Code_BadGateway,
  HTTP_Code_ServUnavail,
  HTTP_Code_GatewayTimeout,
  HTTP_Code_VersionNotSupp,
  HTTP_Code_COUNT
};

struct http_headers {
  unsigned cnt;
  struct head_kv {
    ptrlen key;
    ptrlen_list val;
  } h[32];
};
typedef struct http_headers http_headers;

struct http_req {
  enum HTTP_Method method;
  ptrlen meth,
         uri,
         ver,
         contents;
  http_headers headers;
};
typedef struct http_req http_req;

struct http_resp {
  ptrlen ver,
         code,
         desc,
         contents;
  http_headers headers;
};
typedef struct http_resp http_resp;

enum HTTP_Type {
  HTTP_Type_REQ,
  HTTP_Type_RESP,
  HTTP_Type_DATA
};

struct http {
  enum HTTP_Type type;
  union {
    http_req req;
    http_resp resp;
  } data;
};
typedef struct http http;

size_t http_parse_headers(char *, size_t, http_headers *);
size_t http_parse(char *, size_t, parse_frame *, const parse_status *, http *);
size_t http_dump(const parse_frame *, int opt, FILE *, const http *, const char *);
size_t http_dump_headers(const http_headers *, int opt, FILE *);

int http_is_tcp_port (u16 port);

#endif

