/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * BitTorrent
 *
 * References:
 *
 *  #1 Cohen, Bram. The BitTorrent Protocol Specification Feb 28, 2008 [web page]
 *     <URL: http://bittorrent.org/beps/bep_0003.html> [Accessed Jan 10 2009]
 *  #2 BitTorrent v1.0 Specification [web page]
 *     <URL: http://wiki.theory.org/BitTorrentSpecification> [Accessed Jan 10 2009]
 *
 */

#ifndef BITTORRENT_H
#define BITTORRENT_H

#include "types.h"

/**
 * Fixed-sized header
 * @ref #1 
 */
#pragma pack(push, 1)
struct bt_hdr {
  u8  namelen,
      name[19],
      reserved[8],
      info_hash[20],
      peer_id[20];
};
#pragma pack(pop)
typedef struct bt_hdr bt_hdr;

/**
 * Extensible TLV (technically LTV) msg structure
 * @ref #1 
 */
#pragma pack(push, 1)
struct bt_tlv {
  u32 len;
  u8  type;
};
#pragma pack(pop)
typedef struct bt_tlv bt_tlv;

enum MsgType {
  Choke,
  Unchoke,
  Interested,
  NotInterested,
  Have,
  BitField,
  Request,
  Piece,
  Cancel,
  MsgType_COUNT /* last, special */
};

#pragma pack(push, 1)
struct bt_bitfield {
  u8  bits[1]; /* variable-length */
};
#pragma pack(pop)
typedef struct bt_bitfield bt_bitfield;

#pragma pack(push, 1)
struct bt_have {
  u32 index;
};
#pragma pack(pop)
typedef struct bt_have bt_have;

/**
 * request and cancel messages have the same payload
 */
#pragma pack(push, 1)
struct bt_req {
  u32 index,
      begin,
      length;
};
#pragma pack(pop)
typedef struct bt_req bt_req;
typedef struct bt_req bt_cancel;

#pragma pack(push, 1)
struct bt_piece {
  u32 index,
      begin,
      piece;
};
#pragma pack(pop)
typedef struct bt_piece bt_piece;

#endif

