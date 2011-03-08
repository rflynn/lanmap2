/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * BROWSE
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "report.h"
#include "util.h"
#include "ipv4.h"
#include "smb.h"
#include "browse.h"

static size_t parse(char *, size_t, parse_frame *, const parse_status *);
static size_t dump(const parse_frame *, int options, FILE *);

static int test_smb(const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_SMB, test_smb }
};

/**
 * exported interface
 */
const prot_iface Iface_BROWSE = {
  DINIT(id,           PROT_BROWSE),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "BROWSE"),
  DINIT(propername,   "Microsoft Browser Protocol"),
  DINIT(init,         NULL),
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

static int test_smb(const char *buf, size_t len, const parse_status *st)
{
  const smb_hdr *h = (smb_hdr *)st->frame[st->frames-1].off;
  const smb_trans_req *r;
  size_t namelen;
  assert(PROT_SMB == st->frame[st->frames-1].id);
  if (st->frame[st->frames-1].len < sizeof *h)
    return 0;
  if (SMB_Cmd_TransReq != h->cmd)
    return 0;
  r = (smb_trans_req *)((char *)h + sizeof *h);
  namelen = memcspn((char *)r->name, len - sizeof *h + sizeof *r - 1, "\x00", 1);
  return (16 == namelen && 0 == memcmp(r->name, "\\MAILSLOT\\BROWSE", namelen));
}

static size_t do_parse(browse *, char *, size_t, const parse_status *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
static size_t parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  browse *b = (browse *)buf;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *b > len)
    return 0;
  bytes = do_parse(b, buf + sizeof b->cmd, len - sizeof b->cmd, st);
  if (bytes > 0)
    bytes += sizeof b->cmd; /* includes trailing \0 */
  /* NOTE: bytes will normally == len; HOWEVER we can not assume that it will;
   * BROWSER over LLC pads with zero bytes */
  return bytes;
}

static size_t parse_host (const browse *, char *, size_t, const parse_status *);
static size_t parse_domwg(const browse *, char *, size_t, const parse_status *);
static size_t parse_elect(const browse *, char *, size_t, const parse_status *);
static size_t parse_4    (const browse *, char *, size_t, const parse_status *);

static size_t dump_host (const browse *, char *, size_t, const parse_frame *, FILE *);
static size_t dump_domwg(const browse *, char *, size_t, const parse_frame *, FILE *);
static size_t dump_elect(const browse *, char *, size_t, const parse_frame *, FILE *);

static void   rep_host (char *, size_t, const parse_frame *);

static const struct percmd {
  enum Cmd cmd;
  const char *shortname,
             *longname;
  size_t (*parse)(const browse *, char *, size_t, const parse_status *);
  size_t (*dump) (const browse *, char *, size_t, const parse_frame *, FILE *);
  void   (*rep)(char *, size_t, const parse_frame *);
} PerCmd[] = {
  { 0x0,                  "(0)",          "(0)",                    NULL,       NULL,       NULL     },
  { Cmd_Host,             "HostAnn",      "Host Announce",          parse_host, dump_host,  rep_host },
  { Cmd_AnnounceReq,      "AnnReq",       "Anounce Request",        NULL,       NULL,       NULL     },
  { 0x3,                  "(3)",          "(3)",                    NULL,       NULL,       NULL     },
  { Cmd_4,                "(4)",          "(4)",                    parse_4,    NULL,       NULL     },
  { 0x5,                  "(5)",          "(5)",                    NULL,       NULL,       NULL     },
  { 0x6,                  "(6)",          "(6)",                    NULL,       NULL,       NULL     },
  { 0x7,                  "(7)",          "(7)",                    NULL,       NULL,       NULL     },
  { Cmd_BrowserElectReq,  "BrwsrElecReq", "Browser Elect Request",  parse_elect,dump_elect, NULL     },
  { 0x9,                  "(9)",          "(9)",                    NULL,       NULL,       NULL     },
  { 0xa,                  "(a)",          "(a)",                    NULL,       NULL,       NULL     },
  { Cmd_BackupBrowser,    "Backup Brwsr", "Backup Browser",         NULL,       NULL,       NULL     },
  { Cmd_DomainWorkgroup,  "Dom/Wg Ann",   "Domain/Workgroup Ann.",  parse_domwg,dump_domwg, NULL     },
  { 0xd,                  "(d)",          "(d)",                    NULL,       NULL,       NULL     },
  { 0xe,                  "(e)",          "(e)",                    NULL,       NULL,       NULL     },
  { Cmd_LocalMaster,      "LocalMaster",  "Local Master Announce",  parse_host, dump_host,  rep_host }
};

static const struct percmd * get_percmd(u8 cmd)
{
  const struct percmd *p = NULL;
  if (cmd < sizeof PerCmd / sizeof PerCmd[0])
    p = PerCmd + cmd;
  else
    fprintf(stderr, "!!! Unknown BROWSE cmd (0x%02x)\n", cmd);
  return p;
}

static size_t do_parse(browse *b, char *buf, size_t len, const parse_status *st)
{
  const struct percmd *p = get_percmd(b->cmd);
  size_t bytes = 0;
  if (p) {
    buf[len-1] = '\0'; /* for now, just prevent us from running off the end */
    if (p->parse) {
      bytes = (*p->parse)(b, buf, len, st);
    } else {
      bytes = len;
    }
  }
  return bytes;
}

static size_t dump(const parse_frame *f, int options, FILE *out)
{
  const browse *b = (browse *)f->off;
  char *buf = (char *)b + sizeof b->cmd;
  const struct percmd *p = get_percmd(b->cmd);
  int bytes;
  if (NULL == p || NULL == p->dump)
    bytes = fprintf(out, "No dump for BROWSE cmd 0x%02x\n", b->cmd);
  else {
    bytes = (*p->dump)(b, buf, f->len, f, out);
    if (p->rep)
      (*p->rep)(buf, f->len, f);
  }
  return (size_t)bytes;
}

/**
 * parse host comment at the end;
 * NOTE: this *should* go until the end of the packet; however some instances
 * (i.e. BROWSER over LLC) pad the message with NUL bytes.
 */
static size_t parse_host(const browse *b, char *buf, size_t len, const parse_status *st)
{
  const struct browse_hostann *h = (struct browse_hostann *)buf;
  size_t bytes,
         commentlen;
  if (len < sizeof *h)
    return 0;
  commentlen = memcspn((char *)h->host_comment, len - sizeof *h, "\x00", 1);
  bytes = sizeof *h + commentlen;
  if (bytes > len)
    bytes = len;
  printf("%s %s (bytes=%u):", __FILE__, __func__, (unsigned)bytes);
  dump_chars((char *)h, bytes, stdout);
  fputc('\n', stdout);
  return bytes;
}

static size_t parse_domwg(const browse *b, char *buf, size_t len, const parse_status *st)
{
  const struct dom_wg *d = (struct dom_wg *)buf;
  size_t bytes,
         namelen;
  if (len < sizeof *d)
    return 0;
  namelen = memcspn((char *)d->master_name, len - sizeof *d, "\x00", 1);
  bytes = sizeof *d + namelen;
  printf("%s %s (bytes=%u):", __FILE__, __func__, (unsigned)bytes);
  dump_chars((char *)d, bytes, stdout);
  fputc('\n', stdout);
  assert(bytes == len);
  return bytes;
}

static size_t parse_elect(const browse *b, char *buf, size_t len, const parse_status *st)
{
  struct electreq *e = (struct electreq *)buf;
  size_t bytes,
         namelen;
  if (len < sizeof *e)
    return 0;
  namelen = memcspn((char *)e->name, len - sizeof *e, "\x00", 1);
  bytes = sizeof *e + namelen;
  printf("%s %s (bytes=%u):", __FILE__, __func__, (unsigned)bytes);
  dump_chars((char *)e, bytes, stdout);
  fputc('\n', stdout);
  /* fix endianness */
  e->uptime = ltohl(e->uptime);
  assert(bytes == len);
  return bytes;
}

static size_t parse_4(const browse *b, char *buf, size_t len, const parse_status *st)
{
  struct cmd4 *c = (struct cmd4 *)buf;
  return len;
}

static size_t dump_host(const browse *b, char *buf, size_t len, const parse_frame *f, FILE *out)
{
  const struct browse_hostann *h = (struct browse_hostann *)buf;
  int bytes = fprintf(out,
    "  %s <%s> cmd=0x%02x "
    "upd(cnt=%u period=%lu) hostname=\"%s\" "
    "os=%u.%u browser=%u.%u "
    "sig=0x%04x comment=\"%s\"\n",
    Iface_BROWSE.shortname, PerCmd[b->cmd].shortname, b->cmd,
    h->updatecnt, (unsigned long)h->updateperiod, (char *)h->hostname,
    h->os_maj, h->os_min, h->browser_maj, h->browser_min,
    h->signature, (char *)h->host_comment);
  assert((0x55AA == h->signature || 0xaa55 == h->signature) && "Trying to identify parsing issues");
  return (size_t)bytes;
}

static size_t dump_domwg(const browse *b, char *buf, size_t len, const parse_frame *f, FILE *out)
{
  const struct dom_wg *h = (struct dom_wg *)buf;
  int bytes = fprintf(out,
    "  %s <%s> cmd=0x%02x "
    "upd(cnt=%u period=%lu) workgroup=\"%s\" "
    "os=%u.%u mystery=0x%04lx master=\"%s\"\n",
    Iface_BROWSE.shortname, PerCmd[b->cmd].shortname, b->cmd,
    h->update.cnt, (unsigned long)h->update.period, (char *)h->workgroup,
    h->os_maj, h->os_min, (unsigned long)h->mystery, (char *)h->master_name);
  return (size_t)bytes;
}

static size_t dump_elect(const browse *b, char *buf, size_t len, const parse_frame *f, FILE *out)
{
  const struct electreq *e = (struct electreq *)buf;
  int bytes = fprintf(out,
    "  %s <%s> cmd=0x%02x "
    "desire(nt=%u wins=%u dom=%u brws=%u stdby=%u back=%u) "
    "browser=%u.%u os(nt_srv=%u nt_wrkst=%u wfw=%u) uptime=%lu name=%.*s\n",
    Iface_BROWSE.shortname, PerCmd[b->cmd].shortname, b->cmd,
    e->nt, e->wins, e->domain_master, e->browser_master, e->standby, e->backup,
    e->browser_maj, e->browser_min,
    e->nt_server, e->nt_workstation, e->wfw,
    (unsigned long)e->uptime,
    (int)(f->len - sizeof *e), e->name);
  return (size_t)bytes;
}

static void rep_host(char *buf, size_t len, const parse_frame *f)
{
#ifndef TEST
  const struct browse_hostann *h = (struct browse_hostann *)buf;
  char ipbuf[48];
  char val[256];
  const parse_frame *fi = f-4;//st->frame+st->frames-3;
  if (PROT_IPv4 == fi->id) {
    /* NOTE: may also be LLC or something else */
    const ipv4 *ip = fi->off;
    (void)ipv4_addr_format(ipbuf, sizeof ipbuf, ip->src);
    snprintf(val, sizeof val, "%u.%u", h->os_maj, h->os_min);
    rep_hint("4", ipbuf, "BROWSE.OS", val, -1);
    snprintf(val, sizeof val, "%u.%u", h->browser_maj, h->browser_min);
    rep_hint("4", ipbuf, "BROWSE.Browser", val, -1);
    if ('\0' != h->host_comment[0] && strlen((char *)h->host_comment) == dump_chars_buf2(val, sizeof val, (char *)h->host_comment, strlen((char *)h->host_comment))) {
      /* ensure that parsing was sane */
      rep_hint("4", ipbuf, "BROWSE.Comment", val, -1);
    } else if ('\0' != h->host_comment[0]) {
      assert(0 && "Parsing still broken?!");
    }
  }
#endif
}

#ifdef TEST

static struct {
  size_t smblen;
  char smb[128];
  size_t browselen;
  char browse[128];
} TestCase[] = {
  {
    89, "\xffSMB%\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00)\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00)\x00V\x00\x03\x00\x01\x00\x01\x00\x02\x00:\x00\\MAILSLOT\\BROWSE\x00",
    59, "\x0f\x06\x80\xfc\x0a\x00MAC001B63A495BC\x00\x04\x09\x03\x9a\x84\x00\x0f\x01U\xaaXXXXX\x20XXX"
  },
  { 
    86, "\xffSMB%\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x15\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x15\x00V\x00\x03\x00\x01\x00\x01\x00\x02\x00&\x00\\MAILSLOT\\BROWSE\x00",
    21, "\x08\x01&\x0f\x01\x14\x10\xc2\x12*\x00\x00\x00\x00SALES1\x00"
  },
  {
    92, "\xffSMB\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x44\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x44\x00V\x00\x03\x00\x01\x00\x00\x00\x02\x00U\x00\\MAILSLOT\\BROWSE\x00",
    83,  "\x0f\x00\x80\xfc\x0a\x00PC785018295244\x00\x00\x05\x01\x03\x10\x05\x00\x0f\x01U\xaathe\x20madwomanintheattic's\x20memory box\x00"
  },
  {
    54, "\x11\x00\x00)\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00)\x00V\x00\x03\x00\x01\x00\x01\x00\x02\x00:\x00\\MAILSLOT\\BROWSE\x00",
    40, "\x06\x80\xfc\x0a\x00MAC001B63A495BC\x00\x04\x09\x03\x9a\x84\x00\x0f\x01U\xaaXxxxx\x20Xxx"
  },
  { 
     0, "",
     0, ""
  }
}, *T = TestCase;

extern size_t smb_parse(char *, size_t, parse_frame *, const parse_status *);
extern size_t smb_dump(const parse_frame *, int options, FILE *);

static void test(void)
{
  unsigned i;
  for (i = 0; i < sizeof TestCase / sizeof TestCase[0]; i++) {
    parse_frame pf = { PROT_SMB, T->smblen, T->smb, NULL };
    parse_frame pf2 = { PROT_BROWSE, T->browselen, T->browse, NULL };
    size_t smbbytes, browsebytes;
    /* print */
    printf("#%2u:\n", i);
    printf("  SMB len=%lu ", T->smblen);
    dump_chars(T->smb, T->smblen, stdout);
    fputc('\n', stdout);
    printf("  BROWSE len=%lu ", T->browselen);
    dump_chars(T->browse, T->browselen, stdout);
    fputc('\n', stdout);
    /* parse ip and tcp in order */
    smbbytes = smb_parse(T->smb, T->smblen, &pf, NULL);
    printf("smb parsed %u bytes: ", (unsigned)smbbytes);
    dump_chars((char *)T->smb, smbbytes, stdout);
    fputc('\n', stdout);
    browsebytes = parse(T->browse, T->browselen, &pf2, NULL);
    printf("browse parsed %u bytes: ", (unsigned)browsebytes);
    dump_chars((char *)T->browse, browsebytes, stdout);
    fputc('\n', stdout);
    smb_dump(&pf, 0, stdout);
    dump(&pf2, 0, stdout);
    assert(smbbytes == T->smblen);
    assert(browsebytes == T->browselen);
    T++;
  }
}

int main(void)
{
  test();
  return 0;
}
#endif


