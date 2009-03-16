/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * BitTorrent
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "bittorrent.h"

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump (const parse_frame *, int options, FILE *);

static int test_tcp(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_TCP, test_tcp }
};

/**
 * exported interface
 */
const prot_iface Iface_BitTorrent = {
  DINIT(id,           PROT_BITTORRENT),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "BitTorrent"),
  DINIT(propername,   "BitTorrent"),
  DINIT(init,         init),
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

/*
 * An efficient means of checking whether or not the protocol is BitTorrent in a single comparison
 * 19,'B','i','t'
 */
#ifdef __BIG_ENDIAN
# define BIT19 0x74694213UL
#else
# define BIT19 0x13426974UL
#endif

static int test_tcp(const char *buf, size_t len, const parse_status *st)
{
  const bt_hdr *b = (bt_hdr *)buf;
  return len >= sizeof *b
      && BIT19 == *(u32 *)buf /* check first 4 characters at once */
      && 0 == memcmp("BitTorrent protocol", b->name, sizeof b->name);
}

static size_t do_parse(const bt_hdr *, char *, size_t);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  bt_hdr *b = (bt_hdr *)buf;
  size_t bytes = 0;
  /* sanity check packet */
  if (sizeof *b > len)
    return 0;
  if (len > sizeof *b)
    bytes = do_parse(b, buf + sizeof *b, len - sizeof *b);
  bytes += sizeof *b;
  return bytes;
}

static size_t dump_hex(const u8 *src, size_t srclen, FILE *out)
{
  int bytes = 0;
  while (srclen--)
    bytes += fprintf(out, "%02x", *src++);
  return (size_t)bytes;
}

static size_t parse_have   (void *, size_t);
static size_t parse_request(void *, size_t);

static size_t dump_nodata  (enum MsgType, const void *, size_t, FILE *);
static size_t dump_have    (enum MsgType, const void *, size_t, FILE *);
static size_t dump_bitfield(enum MsgType, const void *, size_t, FILE *);
static size_t dump_request (enum MsgType, const void *, size_t, FILE *);
static size_t dump_piece   (enum MsgType, const void *, size_t, FILE *);
static size_t dump_cancel  (enum MsgType, const void *, size_t, FILE *);

static const struct bytype {
  enum MsgType type;
  const char  *name;
  size_t       minbytes,
             (*parse)(void *, size_t),
             (*dump)(enum MsgType, const void *, size_t, FILE *);
} PerType[MsgType_COUNT] = {
  { Choke,          "Choke",          0,                    NULL,            dump_nodata   },
  { Unchoke,        "Unchoke",        0,                    NULL,            dump_nodata   },
  { Interested,     "Interested",     0,                    NULL,            dump_nodata   },
  { NotInterested,  "Not Interested", 0,                    NULL,            dump_nodata   },
  { Have,           "Have",           sizeof(bt_have),      parse_have,      dump_have     },
  { BitField,       "BitField",       sizeof(bt_bitfield),  NULL,            dump_bitfield },
  { Request,        "Request",        sizeof(bt_req),       parse_request,   dump_request  },
  { Piece,          "Piece",          sizeof(bt_piece),     parse_request,   dump_piece    },
  { Cancel,         "Cancel",         sizeof(bt_cancel),    parse_request,   dump_cancel   }
};

static size_t do_parse(const bt_hdr *h, char *buf, size_t len)
{
  bt_tlv *t = (bt_tlv *)buf;
  if (len < sizeof *t)
    return 0;
  len -= sizeof *t;
  t->len = ntohl(t->len);
  if (t->len-1 > len)
    return 0; /* invalid */
  if (t->type > sizeof PerType / sizeof PerType[0])
    return 0;
  if (NULL == PerType[t->type].parse)
    return sizeof *t + len;
  return sizeof *t + (*PerType[t->type].parse)(buf + sizeof *t, len);
}

/**
 * generic dump for types without payload
 */
static size_t dump_nodata(enum MsgType t, const void *buf, size_t len, FILE *out)
{
  int bytes = fprintf(out, " %s\n", PerType[t].name);
  return (size_t)bytes;
}

static size_t dump_have(enum MsgType t, const void *buf, size_t len, FILE *out)
{
  const bt_have *h = (bt_have *)buf;
  int bytes = fprintf(out, " %s len=%u index=%lu\n",
    PerType[Have].name, len, (unsigned long)h->index);
  return (size_t)bytes;
}

static size_t dump_bitfield(enum MsgType t, const void *buf, size_t len, FILE *out)
{
  const bt_bitfield *b = (bt_bitfield *)buf;
  int bytes = fprintf(out, " %s len=%u ", PerType[BitField].name, len);
  bytes += dump_hex(b->bits, len, out);
  fputc('\n', out);
  bytes++;
  return (size_t)bytes;
}

static size_t dump_request(enum MsgType t, const void *buf, size_t len, FILE *out)
{
  const bt_req *r = (bt_req *)buf;
  int bytes = fprintf(out, " %s len=%u index=%lu begin=%lu length=%lu\n",
    PerType[Request].name, len,
    (unsigned long)r->index, (unsigned long)r->begin, (unsigned long)r->length);
  return (size_t)bytes;
}

static size_t dump_piece(enum MsgType t, const void *buf, size_t len, FILE *out)
{
  const bt_piece *p = (bt_piece *)buf;
  int bytes = fprintf(out, " %s len=%u index=%lu begin=%lu piece=%lu\n",
    PerType[Piece].name, len,
    (unsigned long)p->index, (unsigned long)p->begin, (unsigned long)p->piece);
  return (size_t)bytes;
}

static size_t dump_cancel(enum MsgType t, const void *buf, size_t len, FILE *out)
{
  const bt_cancel *c = (bt_cancel *)buf;
  int bytes = fprintf(out, " %s len=%u index=%lu begin=%lu length=%lu\n",
    PerType[Cancel].name, len,
    (unsigned long)c->index, (unsigned long)c->begin, (unsigned long)c->length);
  return (size_t)bytes;
}

static size_t parse_have(void *buf, size_t len)
{
  bt_have *h = buf;
  h->index = ntohl(h->index);
  return sizeof *h;
}

/**
 * used by request, piece and cancel since the binary structure is identical
 */
static size_t parse_request(void *buf, size_t len)
{
  bt_req *r = buf;
  /* convert endianness */
  r->index  = ntohl(r->index);
  r->begin  = ntohl(r->begin);
  r->length = ntohl(r->length);
  return sizeof *r;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const bt_hdr *b = f->off;
  const bt_tlv *t = (bt_tlv *)((u8 *)f->off + sizeof *b);
  char infobuf[sizeof b->info_hash * 2 + 1],
       peerbuf[sizeof b->peer_id * 2 + 1];
  int bytes;
  dump_hash_buf(infobuf, sizeof infobuf, b->info_hash, sizeof b->info_hash);
  dump_hash_buf(peerbuf, sizeof peerbuf, b->peer_id, sizeof b->peer_id);
  bytes = fprintf(out,
    "%s name=\"%.*s\" reserved=0x%02x%02x%02x%02x%02x%02x info=0x%s peer=0x%s\n",
    Iface_BitTorrent.shortname, b->namelen, (char *)b->name,
    (u8)b->reserved[0], (u8)b->reserved[1], (u8)b->reserved[2], (u8)b->reserved[3],
    (u8)b->reserved[4], (u8)b->reserved[5],
    infobuf, peerbuf);
  if (f->len >= sizeof *b + sizeof *t && PerType[t->type].dump)
    bytes += (*PerType[t->type].dump)(t->type, (void *)((u8 *)t + sizeof *t), f->len - sizeof *b - sizeof *t, out);
  return (size_t)bytes;
}

static int init(void)
{
  char bit19[4] = "\x13""Bit";
  assert(*(u32 *)bit19 == BIT19 && "Fix your endianness");
  return 1;
}

#ifdef TEST

static struct {
  size_t len;
  char txt[256];
} TestCase[] = {

  { 73,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x01\x00"
  },

  { 73,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x01\x01"
  },

  { 73,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x01\x02"
  },

  { 73,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x01\x03"
  },

  { 77,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x05\x04\x00\x00\x00\x00"
  },

  { 74,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x02\x05\xff"
  },
  { 97,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x19\x05\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe"
  },

  { 85,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  },

  { 85,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x01\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  },

  { 85,
    "\x13""BitTorrent protocolex\x00\x00\x00\x00\x00\x00"
    "\x01\x64\xfe\x7e\xf1\x10\x5c\x57\x76\x41\x70\xed\xf6\x03\xc4\x39\xd6\x42\x14\xf1"
    "\x65\x78\x62\x63\x00\x38\x31\x7b\x01\x75\x33\xf4\x1b\x14\x11\xa8\xab\x28\xbb\x54"
    "\x00\x00\x00\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  },

}, *T = TestCase;

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_BITTORRENT, T->len, T->txt, NULL };
    size_t consumed;
    printf("#%2u: ", i);
#if 0
    dump_chars(T->txt, T->len, stdout);
#endif
    fputc('\n', stdout);
    consumed = parse(T->txt, T->len, &pf, NULL);
    assert(consumed == T->len);
    dump(&pf, 0, stdout);
    T++;
  }
}

int main(void)
{
  init();
  test();
  return 0;
}
#endif



