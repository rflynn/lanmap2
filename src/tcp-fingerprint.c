/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * TCP fingerprint creation and reporting
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include "prot.h"
#include "util.h"
#include "report.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp-fingerprint.h"

extern int    tcp_init(void);
extern size_t tcp_parse(char *, size_t, parse_frame *, const parse_status *);
extern size_t tcp_dump(const parse_frame *, int options, FILE *);

/**
 * round TTL up to the next-highest power of two, or 255, in the following fashion:
 *      0-1 ->   1
 *        2 ->   2
 *      3-4 ->   4
 *      5-8 ->   8
 *     9-16 ->  16
 *    17-32 ->  32
 *    33-64 ->  64
 *   65-128 -> 128
 *  129-255 -> 255
 *
 * why? most popular operating systems (but not all) use a power of 2 (or 255) as their original TTL.
 * normalizing the value makes it feasible to exactly match the fingerprint even if we're >0 hops
 * away from the origin.
 *
 * also, the nmap tool cleverly tries to evade fingerprinting by using a psuedo-random TTL on its
 * network scans; this normalization helps us identify its scans.
 *
 * the downside is that this decreases the address space of the fingerprints, causing more overlap,
 * where normally we could identify a TTL of 20 we now have to set the fingerprint to 32 in order
 * to match it.
 */
static u8 ttl_normalize(u8 ttl)
{
  ttl--;
  ttl |= ttl >> 1;
  ttl |= ttl >> 2;
  ttl |= ttl >> 4;
  ttl++;
  return ttl;
}

static ptrdiff_t build_p0f_fingerprint(const tcp *t, size_t tcplen, const ipv4 *ip, size_t iplen, p0f_fingerprint *p)
{
  const u8 *cur = t->opt,
           *end = (u8 *)t + tcplen;
  p->mss = 0;
  p->win.size = t->window;
  p->ttl = ttl_normalize(ip->ttl);
  p->df = ip->flag.dontfrag;
  p->synsize = iplen + tcplen;
  p->optlen = 0;
  memset(&p->q, 0, sizeof p->q);
  p->q.Z = 0 == ip->id;
  p->q.U = !!t->urgptr;
  p->q.X = !!ip->flag.evil;
  p->q.A = !!t->ackno;
  p->q.F = t->psh | t->urg;
  while (cur + 1 < end && p->optlen < sizeof p->opt / sizeof p->opt[0]) {
    const tcp_opt *o = (tcp_opt *)cur;
#if 0
    printf("Opt #%u (%s)", o->type,
      o->type < sizeof PerOpt / sizeof PerOpt[0] ? PerOpt[o->type].shortname : "?!");
#endif
    if (p->optlen > 0 && TCP_Opt_End == p->opt[p->optlen-1].id) {
      /* options past EOL */
      p->q.P = 1;
      break;
    }
    p->opt[p->optlen].id = o->type;
    if (TCP_Opt_End == o->type || TCP_Opt_NOP == o->type) {
      cur++;
    } else {
      /* copy opt-specific ancillary data... */
      switch (o->type){
      case TCP_Opt_MSS:
        if (cur + 2 + 2 <= end) {
          p->opt[p->optlen].n = ntohs(*(u16*)o->val);
          p->mss = p->opt[p->optlen].n;
        }
        break;
      case TCP_Opt_WSOPT:
        if (cur + 2 + 1 <= end)
          p->opt[p->optlen].n = *(u8*)o->val;
        break;
      case TCP_Opt_TSOPT:
        if (cur + 2 + 4 <= end)
          p->opt[p->optlen].n = !!*(u32*)o->val;
        break;
      }
      if (o->len >= 2)
        cur += o->len;
      else
        goto done;
    }
    p->optlen++;
  }
done:
  return cur - (u8*)t;
}

static size_t opt2str(char *buf, size_t len, const p0f_fingerprint *p, int mss_star)
{
  const size_t olen = len;
  unsigned i = 0;
  int used;
  while (len && i < p->optlen) {
    if (i)
      buf++;
    switch (p->opt[i].id) {
    case TCP_Opt_NOP: /* N */
      *buf++ = 'N', len--;
      break;
    case TCP_Opt_End: /* E */
      *buf++ = 'E', len--;
      break;
    case TCP_Opt_WSOPT: /* Wnnn */
      used = snprintf(buf, len, "W%u", p->opt[i].n);
      if (used > 0)
        buf += used, len -= used;
      break;
    case TCP_Opt_MSS: /* Mnnn */
      if (mss_star) {
        used = snprintf(buf, len, "M*");
      } else {
        used = snprintf(buf, len, "M%u", p->opt[i].n);
      }
      if (used > 0)
        buf += used, len -= used;
      break;
    case TCP_Opt_SACKPerm: /* S */
      *buf++ = 'S', len--;
      break;
    case TCP_Opt_TSOPT: /* T[0] */
      *buf++ = 'T', len--;
      if (0 == p->opt[i].n && len)
        *buf++ = '0', len--;
      break;
    default:
      used = snprintf(buf, len, "?%u", p->opt[i].id);
      if (used > 0)
        buf += used, len -= used;
      break;
    }
    if (len)
      *buf = ',', len--;
    i++;
  }
  *buf = '\0';
  return olen - len;
}

static size_t quirk2str(char *buf, size_t len, const p0f_fingerprint *p)
{
  size_t olen = len;
  if (p->q.P) *buf++ = 'P', len--;
  if (p->q.Z) *buf++ = 'Z', len--;
  if (p->q.I) *buf++ = 'I', len--;
  if (p->q.U) *buf++ = 'U', len--;
  if (p->q.X) *buf++ = 'X', len--;
  if (p->q.A) *buf++ = 'A', len--;
  if (p->q.T) *buf++ = 'T', len--;
  if (p->q.F) *buf++ = 'F', len--;
  if (p->q.D) *buf++ = 'D', len--;
  if (p->q.Broken) *buf++ = '!', len--;
  if (len == olen) *buf++ = '.', len--;
  *buf++ = '\0';
  return olen - len;
}

static size_t p0f2str(char *buf, size_t len, const tcp *t, size_t tcplen, const ipv4 *ip, size_t iplen, int mss_star)
{
  size_t bytes = 0;
  p0f_fingerprint p;
  if (build_p0f_fingerprint(t, tcplen, ip, iplen, &p)) {
    char winbuf[16],
         optbuf[256],
         quirkbuf[16];
    u16 mtu = p.mss + 40;
    if (p.mss && 0 == p.win.size % p.mss) {
      snprintf(winbuf, sizeof winbuf, "S%u", p.win.size / p.mss);
    } else if (mtu > 40 && 0 == p.win.size % mtu) {
      snprintf(winbuf, sizeof winbuf, "T%u", p.win.size / mtu);
    } else {
      snprintf(winbuf, sizeof winbuf, "%u", p.win.size);
    }
    opt2str(optbuf, sizeof optbuf, &p, mss_star);
    quirk2str(quirkbuf, sizeof quirkbuf, &p);
    bytes = snprintf(buf, len, "%s:%u:%u:%u:%s:%s",
      winbuf, p.ttl, p.df, p.synsize, optbuf, quirkbuf);
  } else {
    *buf = '\0';
  }
  printf("TCP.SYN.Fingerprint(%u)=%s\n", (unsigned)bytes, buf);
  return bytes;
}

/**
 * given a SYN (not SYN+ACK) TCP packet, generate a p0f-style
 * fingerprint and report it
 */
void tcp_rep_syn(const parse_status *st, const tcp *t, size_t tcplen)
{
#ifndef TEST
  const parse_frame *fi = st->frame + st->frames - 1;
  if (PROT_IPv4 == fi->id) {
    char fpbuf[256],
         ipbuf[48];
    const ipv4 *ip = fi->off;
    size_t fplen;
    (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
    /* generate and report fingerprint with literal MSS value */
     fplen = p0f2str(fpbuf, sizeof fpbuf, t, tcplen, ip, fi->len, 0);
    if (fplen)
      rep_hint("4", ipbuf, "TCP.SYN.Fingerprint", fpbuf, fplen);
    /* generate and report fingerprint with "*" MSS value */
     fplen = p0f2str(fpbuf, sizeof fpbuf, t, tcplen, ip, fi->len, 1);
    if (fplen)
      rep_hint("4", ipbuf, "TCP.SYN.Fingerprint", fpbuf, fplen);
  }
#endif
}

void tcp_rep(const parse_status *st, const tcp *t, size_t tcplen)
{
  if (t->syn && !t->ack)
    tcp_rep_syn(st, t, tcplen);
  else if (!t->ack && !t->syn && !t->fin && !t->rst && !t->psh && !t->urg) {
    /* TCP NULL scan */
#if 0
    tcp_rep_null(st, t, bytes);
#endif
  } else if (t->fin && t->psh && t->urg) {
    /* TCP XMas scan */
  }
}

#ifdef TEST

static struct {
  size_t iplen;
  char ip[32];
  size_t tcplen;
  char tcp[40];
  const char *expected_p0f,
             *proper_p0f;
} TestCase[] = {
  {
    20, "\x45\x00\x00\x30\x72\x60\x40\x00\x80\x06\xe3\x88\x0a\x2b\x61\x51\x42\x98\xf6\xca",
    28, "\x9e\x82\xac\x7f\x9a\x92\xbc\x0a\x00\x00\x00\x00\x70\x02\xff\xff\x3c\xa1\x00\x00\x02\x04\x05\xb4\x01\x01\x04\x02",
    "65535:128:1:48:M1460,N,N,S:.",
    "65535:128:1:48:M1460,N,N,S:."
  },
  {
    20, "\x45\x00\x00\x30\xfe\xfc\x40\x00\x80\x06\xf1\x91\x0a\x2b\x61\x51\x3a\x08\x64\xb5",
    28, "\x3b\x25\x00\x50\xd9\xa1\xbe\xc0\x00\x00\x00\x00\x70\x02\xfc\x00\x86\xbc\x00\x00\x02\x04\x04\xec\x01\x01\x04\x02",
    "64512:128:1:48:M1260,N,N,S:.",
    "64512:128:1:48:M*,N,N,S:."
  },
  { 
    20, "\x45\x10\x00\x3c\x13\x69\x40\x00\x40\x06\x50\x5c\x0a\x2b\x61\x40\x0a\x2b\x61\x51",
    40, "\x04\xbb\x00\x17\xd7\xe1\x1d\xf4\x00\x00\x00\x00\xa0\x02\x16\xd0\x32\xce\x00\x00\x02\x04\x05\xb4\x04\x02\x08\x0a\x1e\x3d\x0e\x9d\x00\x00\x00\x00\x01\x03\x03\x00",
    "",
    ""
  },
  { 
    20, "\x45\x00\x00\x3c\x58\x0f\x00\x00\x33\x06\xab\x2b\xc0\xa8\x01\xc8\xc0\xa8\x01\x69",
    40, "\x83\x9a\x00\x58\xc1\xc9\xd7\xc8\x00\x00\x00\x00\xa0\x02\x10\x00\x17\x2e\x00\x00\x03\x03\x0a\x01\x02\x04\x01\x09\x08\x0a\x3f\x3f\x3f\x3f\x00\x00\x00\x00\x00\x00",
    "4096:51:0:60:W10,N,M265,T,E:P",
    ""
  },
  { 
     0, "",
     0, "",
    "",
    ""
  }
}, *T = TestCase;

extern size_t ipv4_parse(char *, size_t, parse_frame *, const parse_status *);
extern size_t ipv4_dump(const parse_frame *, int options, FILE *);

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    char p0fbuf[256];
    parse_frame pf = { PROT_IPv4, T->iplen, T->ip, NULL };
    parse_frame pf2 = { PROT_TCP, T->tcplen, T->tcp, NULL };
    /* print */
    printf("#%2u:\n", i);
    printf("  IP len=%u ", T->iplen);
    dump_chars(T->ip, T->iplen, stdout);
    fputc('\n', stdout);
    printf("  TCP len=%u ", T->tcplen);
    dump_chars(T->tcp, T->tcplen, stdout);
    fputc('\n', stdout);
    /* parse ip and tcp in order */
    ipv4_parse(T->ip, T->iplen, &pf, NULL);
    tcp_parse(T->tcp, T->tcplen, &pf2, NULL);
    ipv4_dump(&pf, 0, stdout);
    tcp_dump(&pf2, 0, stdout);
    /* generate fingerprint */
    p0f2str(p0fbuf, sizeof p0fbuf, (tcp*)T->tcp, T->tcplen,
                                   (ipv4*)T->ip, T->iplen, 0);
    printf("%s p0f:   %s\nexpected: %s)\n",
      0 == strcmp(p0fbuf, T->expected_p0f) ? "OK" : "!!",
      p0fbuf, T->expected_p0f);
    T++;
  }
}

int main(void)
{
  tcp_init();
  test();
  return 0;
}
#endif

