/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * IPX
 */

#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "util.h"
#include "ieee802_3.h"
#include "linux_sll.h"
#include "ipx.h"

static int    init (void);
static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump (const parse_frame *, int options, FILE *);
static const void * addr_from(const parse_frame *);
static const void * addr_to  (const parse_frame *);

static int test_sll(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_LINUX_SLL, test_sll }
};

/**
 * exported interface
 */
const prot_iface Iface_IPX = {
  DINIT(id,           PROT_IPX),
  DINIT(osi,          OSI_Link),
  DINIT(shortname,    "IPX"),
  DINIT(propername,   "Internetwork Packet Exchange"),
  DINIT(init,         init),
  DINIT(unload,       NULL),
  DINIT(parse,        parse),
  DINIT(dump,         dump),
  DINIT(addr_type,    "X"),
  DINIT(addr_from,    addr_from),
  DINIT(addr_to,      addr_to),
  DINIT(addr_format,  ieee802_3_addr_format),
  DINIT(addr_local,   ieee802_3_addr_local),
  DINIT(parents,      sizeof Test / sizeof Test[0]),
  DINIT(parent,       Test)
};

static int test_sll(const char *buf, size_t len, const parse_status *st)
{
  const linux_sll *s = st->frame[st->frames-1].off;
  return 0x0004 == s->eth_type;
}

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  ipx *x = (ipx *)buf;
  /* sanity check packet */
  if (sizeof *x > len)
    return 0;
  /* convert endianness */
  x->chksum     = ntohs(x->chksum);
  x->pktlen     = ntohs(x->pktlen);
  x->dst.net    = ntohl(x->dst.net);
  x->dst.socket = ntohs(x->dst.socket);
  x->src.net    = ntohl(x->src.net);
  x->src.socket = ntohs(x->src.socket);
  return sizeof *x;
}

static const struct bytype {
  enum IPX_Type type;
  const char *name;
} PerType[] = {
  { IPX_Type_RIP,       "RIP"               },
  { IPX_Type_Echo,      "Echo"              },
  { IPX_Type_Error,     "Error"             },
  { IPX_Type_PEP,       "PEP"               },
  { IPX_Type_SPX,       "SPX"               },
  { IPX_Type_NCP,       "NCP"               },
  { IPX_Type_NB_Bcast,  "NetBIOS Broacast"  }
};

static const struct bysocket {
  enum IPX_Socket socket;
  const char *name;
} PerSocket[] = {
  { IPX_Socket_RIP,       "RIP"             },
  { IPX_Socket_Echo,      "Echo"            },
  { IPX_Socket_Error,     "Error"           },
  { IPX_Socket_NVT,       "NVT"             },
  { IPX_Socket_NCP,       "NCP"             },
  { IPX_Socket_SAP,       "SAP"             },
  { IPX_Socket_RIP2,      "RIP2"            },
  { IPX_Socket_NetBIOS,   "NetBIOS"         },
  { IPX_Socket_Diag,      "Diag"            },
  { IPX_Socket_Serial,    "Serial"          },
  { IPX_Socket_IPX,       "IPX"             },
  { IPX_Socket_NVT2,      "NVT2"            },
  { IPX_Socket_PrintServ, "PrintServer"     },
  { IPX_Socket_TCP_IPXF,  "TCP/IPXF"        },
  { IPX_Socket_UDP_IPXF,  "UDP/IPXF"        },
  { IPX_Socket_IPXF,      "IPXF"            },
  { IPX_Socket_Dynamic,   "Dynamic"         }
};

static const struct bytype * bytype(u8 type)
{
  const struct bytype *t = NULL;
  unsigned i;
  for (i = 0; i < sizeof PerType / sizeof PerType[0]; i++) {
    if (PerType[i].type == type) {
      t = PerType + i;
      break;
    }
  }
  return t;
}

static const struct bysocket * bysocket(u16 socket)
{
  const struct bysocket *s = NULL;
  unsigned i;
  for (i = 0; i < sizeof PerSocket / sizeof PerSocket[0]; i++) {
    if (PerSocket[i].socket == socket) {
      s = PerSocket + i;
      break;
    }
  }
  return s;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const ipx *x = f->off;
  int bytes = fprintf(out, "%s "
    "chksum=0x%04hx pktlen=%hu hops=%u type=0x%02x "
    "dst(net=0x%08lx node=%02x:%02x:%02x:%02x:%02x:%02x socket=%hu) "
    "src(net=0x%08lx node=%02x:%02x:%02x:%02x:%02x:%02x socket=%hu)\n",
    Iface_IPX.shortname,
    x->chksum, x->pktlen, x->hops, x->type,
    (unsigned long)x->dst.net,
    x->dst.m.o[0], x->dst.m.o[1], x->dst.m.o[2], x->dst.m.o[3], x->dst.m.o[4], x->dst.m.o[5],
    x->dst.socket,
    (unsigned long)x->src.net,
    x->src.m.o[0], x->src.m.o[1], x->src.m.o[2], x->src.m.o[3], x->src.m.o[4], x->src.m.o[5],
    x->src.socket);
  return (size_t)bytes;
}

static const void * addr_from(const parse_frame *f)
{
  const ipx *x = f->off;
  return &x->src.m;
}

static const void * addr_to(const parse_frame *f)
{
  const ipx *x = f->off;
  return &x->src.m;
}

static int init(void)
{
  assert(30 == sizeof(ipx));
  return 1;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

