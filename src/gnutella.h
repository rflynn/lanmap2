/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Gnutella - Tasty open source file-sharing protocol
 *
 * Ref:
 *  #1 Limewire "Gnutella Protocol Specification" [web page]
 *     <URL: http://wiki.limewire.org/index.php?title=GDF>
 *     [Accessed Jan 12 2009]
 *  #2 Klingberg, T. "Gnutella 0.6" [web page]
 *     <URL: http://rfc-gnutella.sourceforge.net/src/rfc-0_6-draft.html>
 *     [Accessed Jan 12 2009]
 */

#ifndef GNUTELLA_H
#define GNUTELLA_H

#include "types.h"
#include "http.h"

/**
 * no real reference; just found them in sample protocol messages and
 * by scouring msgboards where admins discuss the best way to block it.
 */
#define GNUTELLA_TCP_PORT   6346
#define GNUTELLA_TCP_PORT2  6347

/*
 * Resource data exchanges between nodes are negotiated using the standard HTTP.
 * The Gnutella network is only used to locate the nodes sharing those resources.
 *
 * @ref #1 S"Characteristics"
 */
struct gnutella {
  http h;
};
typedef struct gnutella gnutella;

/**
 * @ref #2 S2.2.1
 *
 * 2.2.1 Message Header
 *
 * The message header is 23 bytes divided into the following fields.
 *
 *  Bytes:  Description:
 *   0-15    Message ID/GUID (Globally Unique ID)
 *   16      Payload Type
 *   17      TTL (Time To Live)
 *   18      Hops
 *   19-22   Payload Length
 */
#pragma pack(push, 1)
struct gnut_hdr {
  u8  guid[16],
      type,
      ttl,
      hops;
  u16 payload_len;
};
#pragma pack(pop)
typedef struct gnut_hdr gnut_hdr;

/**
 * @ref #2 S2
 */
enum Type {
  Type_Ping     = 0x00,
  Type_Pong     = 0x01,
  Type_Bye      = 0x02,
  Type_Push     = 0x40,
  Type_Query    = 0x80,
  Type_QueryHit = 0x81,
  Type_COUNT /* last, special */
};

/**
 * @ref #2 S2.2.3
 */
#pragma pack(push, 1)
struct pong {
  u16       port;
  ipv4_addr ip;
  u32       filecnt, /* number of shared files */
            kilocnt; /* number of kilobytes of data shared */
  /* optional GGEP extension... */
};
#pragma pack(pop)
typedef struct pong pong;

/**
 * @ref #2 S2.2.5
 */
#pragma pack(push, 1)
struct qry {
  u16 minspeed_kbsec;
  u8  search[1]; /* variable-length, NUL terminated */
  /* optional GGEP block... */
};
#pragma pack(pop)
typedef struct qry qry;

/**
 * Query Hit payload
 * @ref #2 S2.2.6
 */
#pragma pack(push, 1)
struct qryhit {
  u8        hitcnt;
  u16       port;
  ipv4_addr ip;
  u32       speed_kbsec;
  struct hit {
    u32 index,
        bytes;
    u8  name[1]; /* variable-length, NUL-terminated... */
  } hit; /* variable-number ('numhits') elements... */
  /* optional GGEP block... */
};
#pragma pack(pop)
typedef struct qryhit qryhit;

/**
 * Optional extra block in Query Hit payload after
 * qryhit.hit[qryhit.hitcnt] records...
 * @ref #2 S2.2.6
 */
#pragma pack(push, 1)
struct eqhd {
  u32 vendor_code;
  u8  opendata_len,
      opendata[1]; /* variable-length field... */
};
#pragma pack(pop)
typedef struct eqhd eqhd;

/**
 * Push payload
 * @ref #2 S2.2.8
 */
#pragma pack(push, 1)
struct push {
  u8        servent_id[16];
  u32       file_index;
  ipv4_addr ip;
  u16       port;
  /* optional GGEP block... */
};
#pragma pack(pop)
typedef struct push push;

/**
 * Bye payload
 * @ref #2 S2.2.9
 */
#pragma pack(push, 1)
struct bye {
  u16 code;
  u8  descr[1]; /* variable-length, NUL terminated... */
  /* optional GGEP block... */
};
#pragma pack(pop)
typedef struct bye bye;

/**
 * Gnutella Generic Extension Protocol
 * @ref #2 S2.3.1
 */
#pragma pack(push, 1)
struct ggep {
  u8  lastext:1,
      encoding:1,
      compression:1,
      reserved:1,
      idlen:4;
  u8  id[1]; /* variable-length (1-15) */
};
#pragma pack(pop)
typedef struct ggep ggep;




#endif

