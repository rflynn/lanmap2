/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * given the captured data, implement parsing logic
 */

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <pcap.h>
#include "prot.h"
#include "report.h"
#include "logical.h"

extern const prot_iface Iface_Trailing,
                        Iface_Logical,
                        Iface_Linux_SLL,
                        Iface_IEEE802_3,
                        Iface_LLC,
                        Iface_ARP,
                        Iface_IPv4,
                        Iface_ICMP,
                        Iface_IGMPv2,
                        Iface_UDP,
                        Iface_BOOTP,
                        Iface_SSDP,
                        Iface_NBDgm,
                        Iface_NBNS,
                        Iface_SMB,
                        Iface_BROWSE,
                        Iface_TCP,
                        Iface_HTTP,
                        Iface_HTTPS,
                        Iface_TiVoConn,
                        Iface_IPv6,
                        Iface_DNS,
                        Iface_Symbol8781,
                        Iface_CDP,
                        Iface_LLDP,
                        Iface_RADIUS,
                        Iface_STP,
                        Iface_IPX,
                        Iface_SNMP,
                        Iface_NTP,
                        Iface_McAfeeRumor,
                        Iface_RTSP,
                        Iface_MSSQLM,
                        Iface_RASADV,
                        Iface_DHCPv6,
                        Iface_NetBIOS,
                        Iface_BitTorrent,
                        Iface_StormBotnet,
                        Iface_Gnutella,
                        Iface_IRC,
                        Iface_WSDD,
                        Iface_DCERPC,
                        Iface_ESP,
                        Iface_IPP,
                        Iface_DHT;

static prot_mod Prot[PROT_COUNT] = {
  { PROT_UNKNOWN,     &Iface_Trailing,    0, { { { 0, NULL }, 0 } } },
  { PROT_TRAILING,    &Iface_Trailing,    0, { { { 0, NULL }, 0 } } },
  { PROT_LOGICAL,     &Iface_Logical,     0, { { { 0, NULL }, 0 } } },
  { PROT_LINUX_SLL,   &Iface_Linux_SLL,   0, { { { 0, NULL }, 0 } } },
  { PROT_IEEE802_3,   &Iface_IEEE802_3,   0, { { { 0, NULL }, 0 } } },
  { PROT_LLC,         &Iface_LLC,         0, { { { 0, NULL }, 0 } } },
  { PROT_ARP,         &Iface_ARP,         0, { { { 0, NULL }, 0 } } },
  { PROT_IPv4,        &Iface_IPv4,        0, { { { 0, NULL }, 0 } } },
  { PROT_ICMP,        &Iface_ICMP,        0, { { { 0, NULL }, 0 } } },
  { PROT_IGMPv2,      &Iface_IGMPv2,      0, { { { 0, NULL }, 0 } } },
  { PROT_UDP,         &Iface_UDP,         0, { { { 0, NULL }, 0 } } },
  { PROT_BOOTP,       &Iface_BOOTP,       0, { { { 0, NULL }, 0 } } },
  { PROT_SSDP,        &Iface_SSDP,        0, { { { 0, NULL }, 0 } } },
  { PROT_NBDGM,       &Iface_NBDgm,       0, { { { 0, NULL }, 0 } } },
  { PROT_NBNS,        &Iface_NBNS,        0, { { { 0, NULL }, 0 } } },
  { PROT_SMB,         &Iface_SMB,         0, { { { 0, NULL }, 0 } } },
  { PROT_BROWSE,      &Iface_BROWSE,      0, { { { 0, NULL }, 0 } } },
  { PROT_TCP,         &Iface_TCP,         0, { { { 0, NULL }, 0 } } },
  { PROT_HTTP,        &Iface_HTTP,        0, { { { 0, NULL }, 0 } } },
  { PROT_HTTPS,       &Iface_HTTPS,       0, { { { 0, NULL }, 0 } } },
  { PROT_TIVOCONN,    &Iface_TiVoConn,    0, { { { 0, NULL }, 0 } } },
  { PROT_IPv6,        &Iface_IPv6,        0, { { { 0, NULL }, 0 } } },
  { PROT_DNS,         &Iface_DNS,         0, { { { 0, NULL }, 0 } } },
  { PROT_SYMBOL8781,  &Iface_Symbol8781,  0, { { { 0, NULL }, 0 } } },
  { PROT_CDP,         &Iface_CDP,         0, { { { 0, NULL }, 0 } } },
  { PROT_LLDP,        &Iface_LLDP,        0, { { { 0, NULL }, 0 } } },
  { PROT_RADIUS,      &Iface_RADIUS,      0, { { { 0, NULL }, 0 } } },
  { PROT_STP,         &Iface_STP,         0, { { { 0, NULL }, 0 } } },
  { PROT_IPX,         &Iface_IPX,         0, { { { 0, NULL }, 0 } } },
  { PROT_SNMP,        &Iface_SNMP,        0, { { { 0, NULL }, 0 } } },
  { PROT_NTP,         &Iface_NTP,         0, { { { 0, NULL }, 0 } } },
  { PROT_MCAFEE_RUMOR,&Iface_McAfeeRumor, 0, { { { 0, NULL }, 0 } } },
  { PROT_RTSP,        &Iface_RTSP,        0, { { { 0, NULL }, 0 } } },
  { PROT_MSSQLM,      &Iface_MSSQLM,      0, { { { 0, NULL }, 0 } } },
  { PROT_RASADV,      &Iface_RASADV,      0, { { { 0, NULL }, 0 } } },
  { PROT_DHCPv6,      &Iface_DHCPv6,      0, { { { 0, NULL }, 0 } } },
  { PROT_NetBIOS,     &Iface_NetBIOS,     0, { { { 0, NULL }, 0 } } },
  { PROT_BITTORRENT,  &Iface_BitTorrent,  0, { { { 0, NULL }, 0 } } },
  { PROT_STORMBOTNET, &Iface_StormBotnet, 0, { { { 0, NULL }, 0 } } },
  { PROT_GNUTELLA,    &Iface_Gnutella,    0, { { { 0, NULL }, 0 } } },
  { PROT_IRC,         &Iface_IRC,         0, { { { 0, NULL }, 0 } } },
  { PROT_WSDD,        &Iface_WSDD,        0, { { { 0, NULL }, 0 } } },
  { PROT_DCERPC,      &Iface_DCERPC,      0, { { { 0, NULL }, 0 } } },
  { PROT_ESP,         &Iface_ESP,         0, { { { 0, NULL }, 0 } } },
  { PROT_IPP,         &Iface_IPP,         0, { { { 0, NULL }, 0 } } },
  { PROT_DHT,         &Iface_DHT,         0, { { { 0, NULL }, 0 } } }
};

/**
 * map each protocol's 'parent' entries to the protocols they
 * reference; turning them into 'child' entries;
 * this allows 'parent' protocols to not be modified every time
 * we add support for new child protocols; the source code of
 * the children references their parents; but when we're parsing
 * we can quickly
 */
static void map_children(void)
{
  prot_mod *pi = Prot;
  size_t i;
  printf("Linking %u protocols...\n", PROT_COUNT);
  for (i = 0; i < sizeof Prot / sizeof Prot[0]; i++) {
    if (NULL != pi->iface) {
      const prot_parent *pp = Prot[i].iface->parent;
      size_t p;
      if (pp) {
        printf(" (%s <-", Prot[pp->id].iface->shortname);
        fflush(stdout);
      }
      for (p = 0; p < pi->iface->parents; p++) {
        assert(PROT_COUNT > pp->id && "Programmer error");
        printf(" %s", pi->iface->shortname);
        fflush(stdout);
        if (pp->id == pi->id) {
          fprintf(stderr, "(Whoops!!! skipping...) ");
        } else {
          Prot[pp->id].child[Prot[pp->id].children].par.id = pi->id;
          Prot[pp->id].child[Prot[pp->id].children].par.test = pp->test;
          Prot[pp->id].children++;
        }
        fflush(stdout);
        pp++;
      }
      if (pp)
        fputc(')', stdout);
    }
    pi++;
  }
  fputc('\n', stdout);
}

/**
 * 
 */
static void prot_init(void)
{
  prot_mod *pi = Prot;
  size_t i;
  for (i = 0; i < sizeof Prot / sizeof Prot[0]; i++) {
    if (NULL != pi->iface && NULL != pi->iface->init) {
      if (!(*pi->iface->init)()) {
        fprintf(stderr, "initialization of module #%u (%s) failed.\n",
          (unsigned)i, pi->iface->shortname);
        exit(EXIT_FAILURE);
      }
    }
    pi++;
  }
}

void parse_init(void)
{
  map_children();
  prot_init();
}

/**
 * given a buffer and a logical frame in 'st', parse the contents of a
 * captured network packet
 */
static int do_parse(char *buf, size_t len, parse_status *st)
{
  const prot_mod *p = Prot + st->frame[0].id;
  while (len > 0 && st->frames < sizeof st->frame / sizeof st->frame[0]) {
    size_t c = 0; /* child index */
    prot_child *child = (prot_child *)p->child;
    while (c < p->children) {
      if (child->par.test(buf, len, st)) {
        size_t bytes;
        st->frame[st->frames].pass = NULL; /* always set pass to NULL */
        bytes = (*Prot[child->par.id].iface->parse)(buf, len, st->frame + st->frames, st);
        if (0 == bytes) {
          fprintf(stderr, "%s parse failed\n", Prot[child->par.id].iface->shortname);
        } else {
          printf("parsed %s len=%lu bytes=%lu\n",
            Prot[child->par.id].iface->shortname, (unsigned long)len, (unsigned long)bytes);

          st->frame[st->frames].id  = child->par.id;
          st->frame[st->frames].len = bytes;
          st->frame[st->frames].off = buf;
          st->frames++;

          child->cnt++; /* record parse "hit" */
#if 0
          /* move-to-front heuristic */
          if (c > 0 /* already in front */
            && child->cnt > 32 /* avoid spurious initial shuffling */
            && child->cnt >= (child-1)->cnt * 2 /* twice as popular as previous */
          ) {
            /* swap child and child-1 */
            prot_child tmp = *child;
            *child = *(child-1);
            *(child-1) = tmp;
            child = child-1; /* re-assign child to point at original */
          }
#endif
          assert(bytes <= len);
          buf += bytes;
          len -= bytes;
          goto success;
        }
      }
      c++, child++;
    }
    /* searched all child protocols and test/parse failed */
    /* label rest of data as "unknown" */
    st->frame[st->frames].id  = PROT_UNKNOWN;
    st->frame[st->frames].len = len;
    st->frame[st->frames].off = buf;
    st->frames++;
    break;
success:
    p = Prot + child->par.id;
  }
#if 0
  fprintf(stderr, "all done parsing\n");
#endif
  return st->frames;
}

void traffic(const parse_status *st)
{
  const void *src = NULL,
             *dst = NULL;
  unsigned i = st->frames - 1;
  const parse_frame *f = st->frame + i;
  unsigned long encap = 0UL;
  const prot_iface *addr = NULL;
  while (i > 0) {
    char srcbuf[64],
         dstbuf[64];
    const prot_iface *p;
    p = Prot[f->id].iface;
    /* current level defines addresses */
    encap += f->len;
    if (p->addr_from) {
      addr = p;
      src = (*p->addr_from)(f),
      dst = (*p->addr_to)  (f);
      if (!(*p->addr_local)(src) || !(*p->addr_local)(dst)) {
        src = NULL;
        dst = NULL;
      } else {
        (*p->addr_format)(srcbuf, sizeof srcbuf, src);
        (*p->addr_format)(dstbuf, sizeof dstbuf, dst);
      }
    }
    if (src) {
      rep_traf(addr->addr_type, srcbuf,
               addr->addr_type, dstbuf,
               p->shortname, f->len, encap);
    }
    f--;
    i--;
  }
}

#include "util.h"

/**
 *
 */
int parse(char *buf, size_t len, int linktype, parse_status *st)
{
  static logical_frame lf;
  static u32 FrameNo = 0;

#if 1
  printf("len=%u\n", (unsigned)len);
  dump_chars(buf, len, stdout);
  fputc('\n', stdout);
#endif

  /* write logical frame */
  printf("linktype=%d\n", linktype);
  lf.type = (s32)linktype;
  lf.bytes = len;
  lf.id = FrameNo++;
  st->frame[0].id = PROT_LOGICAL;
  st->frame[0].off = &lf;
  st->frame[0].len = len;
  st->frames++;
  return do_parse(buf, len, st);
}


void dump(const parse_status *st)
{
  size_t i = 0;
  const prot_mod *m;
  const parse_frame *f = st->frame;
  /* map each parse frame to the dump function for that protocol */
  while (i < st->frames) {
    m = Prot + f->id;
    (*m->iface->dump)(f, 0, stdout);
    i++;
    f++;
  }
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

