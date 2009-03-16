/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * HTTP
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "ipv4.h"
#include "tcp.h"
#include "http.h"

static size_t _http_parse(char *, size_t, parse_frame *, const parse_status *);
static size_t _http_dump (const parse_frame *, int opt, FILE *);

static int test_tcp_port(const char *, size_t, const parse_status *);
static int test_reqhead(const char *, size_t, const parse_status *);
static int test_resphead(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_TCP, test_tcp_port },
  { PROT_TCP, test_reqhead  },
  { PROT_TCP, test_resphead }
};

/**
 * exported interface
 */
const prot_iface Iface_HTTP = {
  DINIT(id,           PROT_HTTP),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "HTTP"),
  DINIT(propername,   "HyperText Transmission Protocol"),
  DINIT(init,         NULL),
  DINIT(unload,       NULL),
  DINIT(parse,        _http_parse),
  DINIT(dump,         _http_dump),
  DINIT(addr_type,    NULL),
  DINIT(addr_from,    NULL),
  DINIT(addr_to,      NULL),
  DINIT(addr_format,  NULL),
  DINIT(addr_local,   NULL),
  DINIT(parents,      sizeof Test / sizeof Test[0]),
  DINIT(parent,       Test)
};

/**
 * on any IANA-reserved ports should be HTTP
 */
static int test_tcp_port(const char *buf, size_t len, const parse_status *st)
{
  const tcp *t = st->frame[st->frames-1].off;
  return http_is_tcp_port(t->dstport)
      || http_is_tcp_port(t->srcport);
}

static int do_test_http_header(const char *buf, size_t len)
{
  char unused[1024];
  unsigned unused2;
  /* shortest possible header: "A * HTTP/1.1\r\n" */
  /* NOTE: we use this parser for other HTTP-based protocols such
   * as SSDP and RTSP */
  return
    len >= 13 &&
    5 == sscanf(buf, "%31[^ \r\n] %1023[^ \r\n] %31[^/\r\n]/%u.%u\r\n",
      unused, unused, unused, &unused2, &unused2);
}

static int do_test_req_method(const char *buf, size_t len)
{
  return len >= 8 &&
     /* Ref #1 p.35 */
     (  0 == memcmp(buf, "GET ",     4)
     || 0 == memcmp(buf, "HEAD ",    5)
     || 0 == memcmp(buf, "POST ",    5)
     || 0 == memcmp(buf, "PUT ",     4)
     || 0 == memcmp(buf, "OPTIONS ", 8)
     || 0 == memcmp(buf, "DELETE ",  7)
     || 0 == memcmp(buf, "TRACE ",   6)
     || 0 == memcmp(buf, "CONNECT ", 8));
}

/**
 * parse the contents of an HTTP request header into an 'http_req' structure
 * @param buf data; already validated that it contains something that looks like an HTTP header
 * @return number of bytes consumed; 0 means error and 'r' will not be populated
 */
static ptrdiff_t do_parse_req(char *buf, size_t len, http_req *r)
{
  const char *orig = buf;
  size_t l = memcspn(buf, len, " \r\n", 3);
  if (l > 0) {
    /* method */
    r->meth.start = buf;
    r->meth.len = l;
    buf += l, len -= l;
    /* skip whitespace */
    l = memspn(buf, len, " ", 1);
    buf += l, len -= l;
    /* uri */
    l = memcspn(buf, len, " \r\n", 3);
    r->uri.start = buf;
    r->uri.len = l;
    buf += l, len -= l;
    /* skip whitespace */
    l = memspn(buf, len, " ", 1);
    buf += l, len -= l;
    /* version */
    l = memcspn(buf, len, "\r\n", 2);
    r->ver.start = buf;
    r->ver.len = l;
printf("HTTP ver=<%.*s> (%u)\n", r->ver.len, r->ver.start, r->ver.len);
    buf += l, len -= l;
    /* skip newline */
    /* NOTE: we must skip only a single set of "\r\n" */
    if (len >= 2 && '\r' == buf[0] && '\n' == buf[1])
      buf += 2, len -= 2;
  }
#if 0
  /* debug */
  printf("%s ver=<%.*s> buf=<%.*s>\n",
    __func__, (int)r->ver.len, r->ver.start, 20, buf);
  printf("%s -> %u\n", __func__, (unsigned)(buf-orig));
#endif
  return buf - orig;
}

/**
 * test for HTTP request content
 */
static int test_reqhead(const char *buf, size_t len, const parse_status *st)
{
  return do_test_http_header(buf, len);
}

/**
 * test for HTTP response content
 */
static int test_resphead(const char *buf, size_t len, const parse_status *st)
{
  return len > 5 &&
         0 == memcmp(buf, "HTTP/", 5);
}

size_t http_dump_headers(const http_headers *h, int opt, FILE *out)
{
# define DUMP_KEY_ALIGN 24
  static const char Dots[DUMP_KEY_ALIGN] = "........................";
  int bytes = 0;
  unsigned i, j;
  for (i = 0; i < h->cnt; i++) {
    bytes += fprintf(out, "  %.*s%.*s",
      h->h[i].key.len, h->h[i].key.start,
      h->h[i].key.len > DUMP_KEY_ALIGN ? 0 : DUMP_KEY_ALIGN - h->h[i].key.len, Dots);
    for (j = 0; j < h->h[i].val.cnt; j++)
      bytes += fprintf(out, "%.*s",
        h->h[i].val.p[j].len, h->h[i].val.p[j].start);
    fputc('\n', out);
    bytes++;
  }
  return (size_t)bytes;
}

/**
 * 'buf' points at first char in headers, parse them into 'head' and
 * return bytes consumed
 * @note this function is used by other protocols, such as SSDP
 */
size_t http_parse_headers(char *buf, size_t len, http_headers *head)
{
  struct head_kv *kv = head->h;
  const char *orig = buf,
             *end = buf + len;
  size_t skip = 2;
  head->cnt = 0;
  /* FIXME: make sure we don't go further than 'len' */
#if 0
  printf("%s len=%u buf=%.*s\n",
    __func__, (unsigned)len, (unsigned)len, buf);
#endif
  while (
    buf < end
    && 2 == skip
    && head->cnt < sizeof head->h / sizeof head->h[0]
  ) {
    /* "<A><: ><B><\r\n>" */
    ptrlen_list *pl = &kv->val;
    ptrlen *v = pl->p;
    pl->cnt = 0;
    kv->key.start = buf;
    kv->key.len = memcspn(buf, len, ": \r\n", 4);
    buf += kv->key.len;
    len -= kv->key.len;
    skip = memspn(buf, len, ": ", 2);
    buf += skip;
    len -= skip;
    v->start = buf;
    v->len = memcspn(buf, len, "\r\n", 2);
    pl->cnt++;
    buf += v->len;
    len -= v->len;
    skip = memspn(buf, len, "\r\n", 2);
    buf += skip;
    len -= skip;
    head->cnt++;
    v++;
    kv++;
  }
  return (size_t)(buf - orig);
}

/**
 * allocate storage and do real parsing.
 * this is structured like this so other protocols can use http_parse() by
 * supplying their own storage; we'll never need more than 1 http structure
 * ourselves because http cannot contain instances of itself
 */
static size_t _http_parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  static http h;
  return http_parse(buf, len, f, st, &h);
}


/**
 * @return number of octets used by this protocol, or zero upon error
 */
size_t http_parse(char *buf, size_t len, parse_frame *f, const parse_status *st, http *h)
{
  char        scratchbuf[64];
  unsigned    scratchint;
  size_t      olen = len;
  const char *start = buf,
             *end = buf + len;
#if 0
  printf("HTTP %s len=%u bytes=<", __func__, (unsigned)len);
  dump_chars(buf, len, stdout);
  fputc('>', stdout);
  fputc('\n', stdout);
#endif
  if (5 == sscanf(buf, "%31[^ /\r\n]/%u.%u %u %63[^ \r\n]\r\n",
    scratchbuf, &scratchint, &scratchint, &scratchint, scratchbuf)) {
    http_resp *r = &h->data.resp;
    h->type = HTTP_Type_RESP;
    /* TODO: break out to separate function a la do_parse_req() */
    /* something like "HTTP/1.1 301 Moved Permanently" */
    r->ver.start = buf;
    r->ver.len = memcspn(r->ver.start, len, " ", 1);
    r->code.start = r->ver.start + r->ver.len +
            strspn(r->ver.start + r->ver.len, " ");
    r->code.len = strcspn(r->code.start, " ");
    r->desc.start = r->code.start + r->code.len +
            strspn(r->code.start + r->code.len, " ");
    r->desc.len = strcspn(r->desc.start, "\r\n");
    buf = r->desc.start + r->desc.len +
      strspn(r->desc.start + r->desc.len, "\r\n");
    buf += http_parse_headers(buf, len - (buf - start), &r->headers);
    assert(buf-start <= (ptrdiff_t)len);
    r->contents.start = buf;
    r->contents.len = len-(buf-start);
  } else if (do_test_http_header/*do_test_req_method*/(buf, len)) {
    /* something like "GET / HTTP/1.1" */
    size_t consumed;
    h->type = HTTP_Type_REQ;
    consumed = do_parse_req(buf, len, &h->data.req);
    if (consumed != 0) {
      buf += consumed, len -= consumed;
      consumed = http_parse_headers(buf, len, &h->data.req.headers);
      buf += consumed, len -= consumed;
      h->data.req.contents.start = buf;
      h->data.req.contents.len = len;
    }
  } else {
    h->type = HTTP_Type_DATA;
    buf += len;
  }
  f->pass = h;
  printf("%s -> %u\n", __func__, (unsigned)(buf-start));
  /* FIXME: naughty */
#if 0
  assert(end >= buf);
  assert((size_t)(buf-start) <= olen);
  return (size_t)(buf-start);
#else
  return olen;
#endif
}

static size_t dump_req(const parse_frame *f, int opt, FILE *out, const http *h)
{
  const http_req *r = &h->data.req;
  int bytes = fprintf(out,
    "meth=%.*s uri=%.*s ver=%.*s\n",
    r->meth.len, r->meth.start,
    r->uri.len, r->uri.start,
    r->ver.len, r->ver.start);
  bytes += http_dump_headers(&r->headers, opt, out);
  return (size_t)bytes;
}

static size_t dump_resp(const parse_frame *f, int opt, FILE *out, const http *h)
{
  const http_resp *r = &h->data.resp;
  int bytes = fprintf(out, "ver=%.*s code=%.*s (%.*s)\n",
    r->ver.len, r->ver.start,
    r->code.len, r->code.start,
    r->desc.len, r->desc.start);
  bytes += http_dump_headers(&r->headers, opt, out);
  bytes += dump_chars(r->contents.start, r->contents.len, out);
  fputc('\n', out);
  bytes++;
  return (size_t)bytes;
}

static size_t dump_data(const parse_frame *f, int opt, FILE *out, const http *h)
{
  int bytes = fprintf(out, "bytes=%u\n", (unsigned)f->len);
  bytes += dump_bytes(f->off, f->len, out);
  fputc('\n', out);
  bytes++;
  return (size_t)bytes;
}

static size_t _http_dump(const parse_frame *f, int opt, FILE *out)
{
  const http *h = f->pass;
  return http_dump(f, opt, out, h, Iface_HTTP.shortname);
}

/**
 * exposed to other HTTP-based protocols for their use
 */
size_t http_dump(const parse_frame *f, int opt, FILE *out, const http *h, const char *name)
{
  static const struct {
    enum HTTP_Type type;
    const char *name;
    size_t (*dump)(const parse_frame *, int, FILE *, const http *);
  } Dump[] = {
    { HTTP_Type_REQ,  "req",  dump_req  },
    { HTTP_Type_RESP, "resp", dump_resp },
    { HTTP_Type_DATA, "data", dump_data }
  };
  int bytes = fprintf(out, "%s %s ",
    name, Dump[h->type].name);
  bytes += (*Dump[h->type].dump)(f, opt, out, h);
  return (size_t)bytes;
}

int http_is_tcp_port(u16 port)
{
  return
       HTTP_TCP_PORT      == port
    || HTTP_TCP_PORT_ALT  == port
    || HTTP_TCP_PORT_ALT2 == port;
}

static const char *Meth[] = {
  "(None)",
  "OPTIONS",
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "DELETE",
  "TRACE",
  "CONNECT",
  "Extension"
};

static struct code {
  enum HTTP_Code code;
  enum HTTP_Code_Type type;
  const char key[3];
} Code[HTTP_Code_COUNT] = {
  { HTTP_Code_None,            HTTP_Code_Type_None,     "\0\0\0" },
  { HTTP_Code_Continue,        HTTP_Code_Type_Info,     "100" },
  { HTTP_Code_SwitchProt,      HTTP_Code_Type_Info,     "101" },
  { HTTP_Code_OK,              HTTP_Code_Type_Success,  "200" },
  { HTTP_Code_Created,         HTTP_Code_Type_Success,  "201" },
  { HTTP_Code_Accepted,        HTTP_Code_Type_Success,  "202" },
  { HTTP_Code_NonAuthInfo,     HTTP_Code_Type_Success,  "203" },
  { HTTP_Code_NoContent,       HTTP_Code_Type_Success,  "204" },
  { HTTP_Code_ResetContent,    HTTP_Code_Type_Success,  "205" },
  { HTTP_Code_PartContent,     HTTP_Code_Type_Success,  "206" },
  { HTTP_Code_MultChoice,      HTTP_Code_Type_Redir,    "300" },
  { HTTP_Code_MovedPerm,       HTTP_Code_Type_Redir,    "301" },
  { HTTP_Code_Found,           HTTP_Code_Type_Redir,    "302" },
  { HTTP_Code_SeeOther,        HTTP_Code_Type_Redir,    "303" },
  { HTTP_Code_NotMod,          HTTP_Code_Type_Redir,    "304" },
  { HTTP_Code_UseProxy,        HTTP_Code_Type_Redir,    "305" },
  { HTTP_Code_TempRedir,       HTTP_Code_Type_Redir,    "307" },
  { HTTP_Code_BadReq,          HTTP_Code_Type_CliErr,   "400" },
  { HTTP_Code_Unauth,          HTTP_Code_Type_CliErr,   "401" },
  { HTTP_Code_PayReq,          HTTP_Code_Type_CliErr,   "402" },
  { HTTP_Code_Forbid,          HTTP_Code_Type_CliErr,   "403" },
  { HTTP_Code_NotFound,        HTTP_Code_Type_CliErr,   "404" },
  { HTTP_Code_MethodNotAllow,  HTTP_Code_Type_CliErr,   "405" },
  { HTTP_Code_NotAcc,          HTTP_Code_Type_CliErr,   "406" },
  { HTTP_Code_ProxyAuthReq,    HTTP_Code_Type_CliErr,   "407" },
  { HTTP_Code_ReqTimeout,      HTTP_Code_Type_CliErr,   "408" },
  { HTTP_Code_Conflict,        HTTP_Code_Type_CliErr,   "409" },
  { HTTP_Code_Gone,            HTTP_Code_Type_CliErr,   "410" },
  { HTTP_Code_LenReq,          HTTP_Code_Type_CliErr,   "411" },
  { HTTP_Code_PrecFail,        HTTP_Code_Type_CliErr,   "412" },
  { HTTP_Code_ReqEntTooLarge,  HTTP_Code_Type_CliErr,   "413" },
  { HTTP_Code_ReqURITooLarge,  HTTP_Code_Type_CliErr,   "414" },
  { HTTP_Code_UnsupMediaType,  HTTP_Code_Type_CliErr,   "415" },
  { HTTP_Code_ReqRangeBad,     HTTP_Code_Type_CliErr,   "416" },
  { HTTP_Code_ExpectFail,      HTTP_Code_Type_CliErr,   "417" },
  { HTTP_Code_IntServErr,      HTTP_Code_Type_ServErr,  "500" },
  { HTTP_Code_NotImp,          HTTP_Code_Type_ServErr,  "501" },
  { HTTP_Code_BadGateway,      HTTP_Code_Type_ServErr,  "502" },
  { HTTP_Code_ServUnavail,     HTTP_Code_Type_ServErr,  "503" },
  { HTTP_Code_GatewayTimeout,  HTTP_Code_Type_ServErr,  "504" },
  { HTTP_Code_VersionNotSupp,  HTTP_Code_Type_ServErr,  "505" }
};

#ifdef TEST

static struct {
  size_t len;
  char txt[512];
} TestCase[] = {
  { 0, ""                    },
  { 1, "a"                   },
  { 1, "\0"                  },
  { 1, "\r"                  },
  { 1, "\n"                  },
  { 1, " "                   },
  { 1, ":"                   },
  { 2, " :"                  },
  { 2, "::"                  },
  { 2, "a:"                  },
  { 2, "\r\n"                },
  { 3, "\r\n\r"              },
  { 4, "\r\n\r\n"            },
  { 5, "\r\n\r\n\r"          },
  { 6, "\r\n\r\n\r\n"        },
  { 3, "a: "                 },
  { 3, "a: "                 },
  { 4, "a: b"                },
  { 4, "a: \r"               },
  { 4, "a: \n"               },
  { 5, "a: b\r"              },
  { 5, "a: b\r"              },
  { 6, "a: b\r\n"            },
  { 13, "a: b\r\nc:d\r\n\r\n"}
}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    http_headers h;
    size_t bytes;
    printf("#%2u: ", i);
    dump_chars(T->txt, T->len, stdout);
    fflush(stdout);
    memset(&h, 0, sizeof h);
    bytes = http_parse_headers(T->txt, T->len, &h);
    printf(" len=%u parsed=%u\n", (unsigned)T->len, (unsigned)bytes);
    assert(bytes <= T->len);
    T++;
  }
}

int main(void)
{
  test();
  return 0;
}
#endif

