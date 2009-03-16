/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2009 Ryan Flynn
 * All rights reserved.
 */

#ifndef ICMP_FINGERPRINT_H
#define ICMP_FINGERPRINT_H

#include "types.h"
#include "report.h"
#include "util.h"
#include "ipv4.h"
#include "icmp.h"

struct echo_fingerprint {
  enum Type type;  /* ICMP type */
  u8        ttl,   /* IP TTL */
            idz:1, /* is IP id zero? */
            df:1;  /* is IP df set? */
  unsigned  len;   /* echo payload */
  const u8 *payload;
};
typedef struct echo_fingerprint echo_fingerprint;

void report_echo_fingerprint(const icmp *i, size_t len, const parse_status *st);
void dump_muss_payload(char *buf, size_t buflen, const u8 *src, size_t srclen);

#endif

