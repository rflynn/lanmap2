/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * ICMP Fingerprint - 
 */

#include <assert.h>
#include <stdio.h>
#include "types.h"
#include "prot.h"
#include "util.h"
#include "icmp.h"
#include "icmp-fingerprint.h"

extern struct permsg PerMsg[Type_COUNT];

/**
 * Mike Muuss who wrote the original 'ping' program had it include a payload of
 * an 8-byte binary timestamp followed by 48 bytes of consecutive values \x08-\x37.
 * 'ping' includes an option to set the size of the payload, so we're looking for
 * a payload that contains at least 8 bytes with no discernible pattern, optionally
 * followed by an incrementing payload.
 */
static int is_muuss_payload(const u8 *d, size_t len)
{
  return 56 == len;
#if 0 /* this is too strict */
  unsigned i;
  if (len < 8) /* too short timestamp */
    return 0;
  if (len > 8 && d[8] != '\x08')
    return 0;
  /* 
   * if there is some kind of pattern to the first
   * 8 octets then it is not a Muss payload.
   * this avoid false positives on payloads of all zeroes, all 0xFFs
   * or all incrementing or decrementing payloads without a timestamp
   */
  if (d[1] - d[0] == d[2] - d[1] &&
      d[2] - d[1] == d[3] - d[2] &&
      d[3] - d[2] == d[4] - d[3] &&
      d[4] - d[3] == d[5] - d[4] &&
      d[5] - d[4] == d[6] - d[5] &&
      d[6] - d[5] == d[7] - d[6])
    return 0;
  /* we know that s[8] is \x08; check the rest of the payload for
   * none-consecutively-incrementing octet sequences */
  for (i = 9; i < len; i++) {
    if (d[i] != d[i-1]+1)
      return 0;
  }
  return 1;
#endif
}

void dump_muss_payload(char *buf, size_t buflen, const u8 *src, size_t srclen)
{
  assert(srclen >= 8);
  snprintf(buf, buflen, "........");
  if (buflen > 9)
    dump_chars_buf(buf+8, buflen-8, (char *)(src+8), srclen-8);
}

static void fprint2str(char *buf, size_t len, const echo_fingerprint *f)
{
  int used = snprintf(buf, len, "%s,ttl=%u,idz=%u,df=%u,bytes=%u,payload=",
    PerMsg[f->type].shortname, f->ttl, f->idz, f->df, f->len);
  if (used > 0) {
    if (is_muuss_payload(f->payload, f->len))
      dump_muss_payload(buf+used, len-used, f->payload, f->len);
    else
      dump_chars_buf(buf+used, len-used, (char *)f->payload, f->len);
  }
}

/**
 * @note called in context of 'parse', so parse stack
 */
void report_echo_fingerprint(const icmp *i, size_t len, const parse_status *st)
{
  if (PROT_IPv4 == st->frame[st->frames-1].id) {
    char fbuf[1500 * 4],
        ipbuf[48];
    const ipv4 *ip = st->frame[st->frames-1].off;
    size_t flen;
    echo_fingerprint f = {
      i->head.type, ip->ttl, !ip->id, !!ip->flag.dontfrag,
      len - (i->data.echo.payload - (u8*)i), i->data.echo.payload
    };
    (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
    fprint2str(fbuf, sizeof fbuf, &f);
    DEBUGF(__FILE__, __LINE__, "ICMP.Echo.Fingerprint %s\n", fbuf);
    rep_hint("4", ipbuf, "ICMP.Echo.Fingerprint", fbuf, -1);
  }
}

