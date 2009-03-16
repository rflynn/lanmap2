/* ex: set ff=dos: */
/* $Id$ */
/*
 * Copyright 2009 Ryan Flynn
 */
/*
 * Implementation of p0f TCP SYN fingerprints so we can use the excellent
 * p0f2 fingerprint database. Thanks Mike.
 */

#ifndef TCP_FINGERPRINT_H
#define TCP_FINGERPRINT_H

#include "types.h"
#include "tcp.h"

/**
 * 
 */
struct p0f_opt {
  enum TCP_Opt id;
  u16 n; /* W, M, T[0] or ?n */
};
typedef struct p0f_opt p0f_opt;

struct p0f_fingerprint {
  u16 mss;
  struct {
    u32 any:1,
        mod:1,
        S:1,
        T:1,
        size:28;
  } win;
  u8  ttl,
      df:1,
      synsize;
  unsigned optlen;
  p0f_opt opt[20];
	struct {
		unsigned P:1,
		         Z:1,
						 I:1,
						 U:1,
						 X:1,
						 A:1,
						 T:1,
						 F:1,
						 D:1,
						 Broken:1;
	} q;
};
typedef struct p0f_fingerprint p0f_fingerprint;

void tcp_rep(const parse_status *, const tcp *, size_t tcplen);

#endif

