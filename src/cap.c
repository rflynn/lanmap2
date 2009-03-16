/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * 
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pcap.h>
#include "report.h"
#include "util.h"
#include "env.h"
#include "types.h"
#include "prot.h"

#define PACKET_BUFLEN   (64 * 1024)
#define IFACE_MAX       2

extern int parse_init(void);
extern int parse(char *buf, size_t len, int linktype, parse_status *);
extern void dump(const parse_status *);
extern void traffic(const parse_status *);

struct netiface {
  char        name[64];
  bpf_u_int32 net,
              mask;
  pcap_t     *pcap;
} NetIface[IFACE_MAX];
unsigned                  NetIfaces  = 0;
int                       Shutdown   = 0;
unsigned                  Verbosity  = 2;
static long               SelectFreq = 1;
static struct bpf_program Filter;
static char              *Filter_Str = "not tcp port 22"/*"!tcp"*/;

static int netiface_add(const char *name)
{
  struct netiface *n = NetIface + NetIfaces;
  if (Verbosity >= 2)
    printf("Adding dev '%s'...\n", name);
  strlcpy(n->name, name, sizeof n->name);
  NetIfaces++;
  assert(NetIfaces < sizeof NetIface / sizeof NetIface[0]);
  return 1;
}

/**
 * print all network interfaces to stdout
 */
static int iface_list(void)
{
  static char errbuf[PCAP_ERRBUF_SIZE];
  int ok = 1;
  pcap_if_t *alldevs,
            *dev;
  int i;
  if (-1 == pcap_findalldevs(&alldevs, errbuf)){
    fprintf(stderr,"Error finding devices: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  printf("Devices\n");
  for (i = 0, dev = alldevs; dev; dev = dev->next, i++)
    printf("  %-16s %s\n", dev->name,
      (NULL == dev->description ? "" : dev->description));
  if (0 == i) {
    fprintf(stderr, "No interfaces found!\n");
#ifdef WIN32
    fprintf(stderr, "Ensure WinPcap is installed; see http://www.winpcap.org/\n"
                    "Ensure the service is running and you have appropriate access.\n"
                    "LANMap's corporate customers with lucrative support contracts may override this error by pressing the 'Just Make It Work!' button.");
#else /* UNIX-ish */
    if (0 != geteuid())
      fprintf(stderr, "You may want to run as root.\n");
#endif
    ok = 0;
  }
  pcap_freealldevs(alldevs);
  return ok;
}

/**
 * interfaces are set up in NetIface[], listen!
 */
static int do_listen(void)
{
    /* all ifaces set up... */
    /* FIXME: how do i deal with one iface going down and the others staying up? */
  unsigned i;
  struct timeval tv;
#ifdef WIN32
  HANDLE handles[IFACE_MAX];
#else
  int fds[IFACE_MAX];
  fd_set rd;
  int fdmax = -1;
#endif
  /* initial setup for select()ing */
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  for (i = 0; i < NetIfaces; i++) {
    struct netiface *n = NetIface + i;
#ifdef WIN32
    handles[i] = pcap_getevent(n->pcap);
#else
    fds[i] = pcap_get_selectable_fd(n->pcap);
    if (fds[i] > fdmax)
      fdmax = fds[i];
#endif
  }
  while (0 == Shutdown) {
    static int CountdownToDoom = 0;
    int sel;
#ifdef WIN32
    sel = WaitForMultipleObjects((DWORD)NetIfaces, handles, TRUE, (long)SelectFreq * 1000);
#else
    FD_ZERO(&rd);
    for (i = 0; i < NetIfaces; i++)
      FD_SET(fds[i], &rd);
    sel = select(fdmax + 1, &rd, NULL, NULL, NULL);
#endif
    switch (sel) {
#ifdef WIN32
    case WAIT_FAILED:
#else
    case -1: /* error */
#endif
      perror("select");
      break;
#ifdef WIN32
    case WAIT_TIMEOUT:
#else
    case 0: /* timeout */
#endif
      fprintf(stderr, "timeout...\n");
      continue;
      break;
    default: /* one or more readable */
      for (i = 0; i < NetIfaces; i++) {
        struct netiface *n = NetIface + i;
        struct pcap_pkthdr *header;
        char *packet;
        int cap;
#ifdef WIN32
        if (WAIT_OBJECT_0 + i != sel) {
#else
        if (!FD_ISSET(fds[i], &rd)) {
#endif
          continue;
        }
        /* ok, there should be a packet waiting for us... */
        cap = pcap_next_ex(n->pcap, &header, (const u_char **)&packet);
        switch (cap) {
        case -1: /* err */
          break;
        case 0: /* timeout */
          break;
        case 1: /* ok */
        { /* case scope */
          static parse_status st;
          st.frames = 0;
          parse(packet, header->len, pcap_datalink(n->pcap), &st);
          traffic(&st);
#if 1
          dump(&st);
#endif


#if 0
          /*
           * Crash if we receive data that we did not parse,
           * with the following exceptions...
           */
          if (st.frame[st.frames-1].id == PROT_UNKNOWN
              /* enumerate all cases where we know we get unknown bytes */
              && !(
                /* ethernet frames are often padded with garbage to meet 60 bytes */
                (PROT_IEEE802_3 == st.frame[1].id && 60 == st.frame[0].len)
                /* junk after LLC... */
                || (PROT_STP == st.frame[st.frames-2].id && 7 == st.frame[st.frames-1].len)
                /* junk after SMB over LLC... */
                || (PROT_SMB == st.frame[st.frames-2].id && PROT_LLC == st.frame[2].len)
                /* junk zeroes after BOOTP */
                || (PROT_BOOTP == st.frame[st.frames-2].id &&
                  allzeroes(st.frame[st.frames-1].off, st.frame[st.frames-1].len))
                /* junk after LLDP... */
                || (PROT_LLDP == st.frame[st.frames-2].id && 2 == st.frame[st.frames-1].len)
                /* mysterious message */
                || (PROT_LLC == st.frame[2].id && 82 == st.frame[0].len)
                /* TCP payload */
                || (PROT_TCP == st.frame[st.frames-2].id)
                /* ARP oftens contains garbage */
                || (PROT_ARP == st.frame[st.frames-2].id)
              )) {
            abort();
          }
#endif


#if 0
          /* 
           * the 'gprof' profiling tool requires a clean stop
           * of the program being profiled in order to work.
           * this causes that
           */
          if (CountdownToDoom++ > 4000)
            Shutdown = 1;
#endif




        }
          break;
        default:
          break;
        }
#ifdef WIN32
        break; /* WaitForMultipleObjects only returns the first available, not all */
#endif
      }
      break;
    } /* switch */
  } /* read loop */
  if (Verbosity >= 2) {
    printf("interfaces");
    for (i = 0; i < NetIfaces; i++)
      printf(" %s", NetIface[i].name);
    printf(" down...\n");
  }
  return 1; 
}

/**
 * main loop
 */
static int listen(void)
{
  static char errbuf[PCAP_ERRBUF_SIZE];
  char *dev;
  unsigned i;
  /* listen loop */
  do { 
    int promisc = 1;
    if (0 == NetIfaces) { /* no devs specified, find one */
      dev = pcap_lookupdev(errbuf);
      if (NULL == dev) {
        fprintf(stderr, "Couldn't find default interface: %s\n", errbuf);
        return 0;
      }
      if (Verbosity >= 1)
        printf("Defaulting to dev '%s'\n", dev);
      netiface_add(dev);
    }
    /* set up each iface */
    for (i = 0; i < NetIfaces; i++) {
      struct netiface *n = NetIface + i;
#ifdef WIN32
      promisc = 1;
#else
      promisc = (0 == geteuid());
#endif
      if (Verbosity >= 1)
        printf("opening dev '%s' in %s mode...\n",
          n->name, promisc ? "promiscuous" : "normal");
      n->pcap = pcap_open_live(n->name, PACKET_BUFLEN, promisc, 0, errbuf);
      if (!n->pcap) {
        fprintf(stderr, "Can't open interface '%s'! %s\n", n->name, errbuf);
        fprintf(stderr, "Have you specified an interface with -i?. See -h for more -i info.\n");
        return 0;
      }
      if (-1 == pcap_lookupnet(n->name, &n->net, &n->mask, errbuf)) {
        fprintf(stderr, "Can't get netmask for interface '%s': %s, continuing...\n",
          n->name, errbuf);
        /* no ip address up?! keep on truckin... */
      }
  
      /* TODO: human-readable output, perhaps? */
      if (Verbosity >= 2)
        printf("interface '%s' net: 0x%08X, mask: 0x%08X\n",
          n->name, n->net, n->mask);
    
      /* set filter if we've been supplied one and we've got an ip addres... */
      printf("Applying Filter_Str=\"%s\"...\n", Filter_Str);
      if (NULL != Filter_Str && 0 != n->net && 0 != n->mask) {
        if (-1 == pcap_compile(n->pcap, &Filter, Filter_Str, 0, n->net)) {
          fprintf(stderr, "Can't compile filter '%s': %s. quitting\n",
            Filter_Str, pcap_geterr(n->pcap));
          return 0;
        }
        if (-1 == pcap_setfilter(n->pcap, &Filter)) {
          fprintf(stderr, "Can't install filter '%s': %s. quitting\n",
            Filter_Str, pcap_geterr(n->pcap));
          return 0;
        }
      }
    }
    do_listen();
  } while (!Shutdown);
  return 0;
}

int main(void)
{
  rep_init(stderr);
  parse_init();
  (void)iface_list();
  listen();
  return 0;
}

