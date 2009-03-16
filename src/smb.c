/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * SMB
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
#include "ipv4.h" /* reporting */
#include "smb.h"

int    smb_init (void);
size_t smb_parse(char *, size_t, parse_frame *, const parse_status *);
size_t smb_dump (const parse_frame *, int options, FILE *);

static int test_nbdgm  (const char *, size_t, const parse_status *);
static int test_netbios(const char *, size_t, const parse_status *);
static int test_tcp    (const char *, size_t, const parse_status *);
static const prot_parent Test[] = {
  { PROT_NBDGM,   test_nbdgm   },
  { PROT_NetBIOS, test_netbios },
  { PROT_TCP,     test_tcp     }
};

/**
 * exported interface
 */
const prot_iface Iface_SMB = {
  DINIT(id,           PROT_SMB),
  DINIT(osi,          OSI_App),
  DINIT(shortname,    "SMB"),
  DINIT(propername,   "Server Message Block"),
  DINIT(init,         smb_init),
  DINIT(unload,       NULL),
  DINIT(parse,        smb_parse),
  DINIT(dump,         smb_dump),
  DINIT(addr_type,    NULL),
  DINIT(addr_from,    NULL),
  DINIT(addr_to,      NULL),
  DINIT(addr_format,  NULL),
  DINIT(addr_local,   NULL),
  DINIT(parents,      sizeof Test / sizeof Test[0]),
  DINIT(parent,       Test)
};

static int test_nbdgm(const char *buf, size_t len, const parse_status *st)
{
  return len >= sizeof(smb_hdr)
    && 0 == memcmp("\xffSMB", buf, 4);
}

static int test_netbios(const char *buf, size_t len, const parse_status *st)
{
  return len >= sizeof(smb_hdr)
    && 0 == memcmp("\xffSMB", buf, 4);
}

static int test_tcp(const char *buf, size_t len, const parse_status *st)
{
  return len >= sizeof(smb_hdr)
    && 0 == memcmp("\xffSMB", buf, 4);
}

static size_t do_parse(char *buf, size_t len, const smb_hdr *);

/**
 * @return number of octets used by this protocol, or zero upon error
 */
size_t smb_parse(char *buf, size_t len, parse_frame *f, const parse_status *st)
{
  smb_hdr *h = (smb_hdr *)buf;
  size_t bytes;
  /* sanity check packet */
  if (sizeof *h > len)
    return 0;
  /* convert endianness */
  h->treeid = ntohs(h->treeid);
  h->procid = ntohs(h->procid);
  h->userid = ntohs(h->userid);
  bytes = do_parse(buf + sizeof *h, len - sizeof *h, h);
#if 1
  printf("%s %s do_parse=%u bytes: ",
    __FILE__, __func__, (unsigned)bytes);
  dump_chars(buf + sizeof *h, bytes, stdout);
  fputc('\n', stdout);
#endif
  bytes += sizeof *h;
  return bytes;
}

static size_t do_dump(const parse_frame *, const char *, size_t, int, FILE *, const smb_hdr *);
size_t smb_dump(const parse_frame *f, int opt, FILE *out)
{
  const smb_hdr *h = (smb_hdr *)f->off;
  int bytes = fprintf(out,
    "%s cmd=0x%02x() err=%u errcode=%hu "
    "lckrd=%u rcvbufpst=%u casesens=%u canonpath=%u oplck=%u notify=%u reqresp=%u\n",
    Iface_SMB.shortname, h->cmd, h->err, ntohs((u16)((h->errcode[0] << 8) | h->errcode[1])),
    h->lckrd, h->rcvbufpst, h->casesens, h->canonpath, h->oplck, h->notify, h->reqresp);
  bytes += do_dump(f, (char *)h + sizeof *h, f->len - sizeof *h, opt, out, h);
  return (size_t)bytes;
}


/**
 * calculate the length, in bytes, of the next layer after the header
 */
static size_t do_calc_len(const char *buf, size_t len, const smb_hdr *h)
{
  size_t bytes = 0;
  switch ((enum SMB_Cmd)h->cmd) {
  case SMB_Cmd_TransReq:
  { /* TODO: break out into own function */
    smb_trans_req *r = (smb_trans_req *)buf;
    if (sizeof *r > len)
      return len;
    /* calculate length of name */
    bytes = memcspn((char *)r->name, len - sizeof *r - 1, "\x00", 1);
    bytes += sizeof *r; /* includes trailing \0 */
  }
    break;
  default:
    break;
  }
  return bytes;
}

/**
 * SMB header has been parsed, parse rest of msg
 * @return number of bytes consumed
 */
static size_t do_parse(char *buf, size_t len, const smb_hdr *h)
{
  size_t bytes = 0;
  printf("do_parse len=%u buf=", (unsigned)len);
  dump_chars(buf, len, stdout);
  fputc('\n', stdout);
  switch ((enum SMB_Cmd)h->cmd) {
  case SMB_Cmd_TransReq:
  { /* TODO: break out into own function */
    size_t namelen;
    smb_trans_req *r = (smb_trans_req *)buf;
    if (sizeof *r > len)
      return 0;
    /* convert endianness */
    r->totalparam       = ltohs(r->totalparam);
    r->totaldata        = ltohs(r->totaldata);
    r->maxparam         = ltohs(r->maxparam);
    r->maxdata          = ltohs(r->maxdata);
    r->param            = ltohs(r->param);
    r->paramoffset      = ltohs(r->paramoffset);
    r->data             = ltohs(r->data);
    r->dataoffset       = ltohs(r->dataoffset);
    r->mailslot.opcode  = ltohs(r->mailslot.opcode);
    r->mailslot.priority= ltohs(r->mailslot.priority);
    r->mailslot.class_  = ltohs(r->mailslot.class_);
    r->mailslot.bytes   = ltohs(r->mailslot.bytes);
    /* calculate length of name */
    namelen = memcspn((char *)r->name, len - sizeof *r - 1, "\x00", 1);
    bytes = namelen + sizeof *r; /* includes trailing \0 */
  }
    break;
  default:
    break;
  }
  return bytes;
}

static size_t do_dump(const parse_frame *pf, const char *buf, size_t len, int opt, FILE *out, const smb_hdr *h)
{
  int bytes = 0;
  switch ((enum SMB_Cmd)h->cmd) {
  case SMB_Cmd_TransReq:
  { /* TODO: break out into own function */
    smb_trans_req *r = (smb_trans_req *)buf;
    if (sizeof *r <= len) {
      /* find where browse is */
      size_t offset = do_calc_len(buf, len, h);
      bytes += fprintf(out,
        "  TransReq wct=%u param(total=%hu max=%u cnt=%u offset=%u) "
                           "data(total=%hu max=%u cnt=%u offset=%u) "
                           "timeout=%lu name=\"%s\"\n",
        r->wct, r->totalparam, r->maxparam, r->param, r->paramoffset,
                r->totaldata,  r->maxdata,  r->data,  r->dataoffset,
        (unsigned long)r->timeout, r->name);
    }
  }
    break;
  default:
    break;
  }
  return (size_t)bytes;
}

int smb_init(void)
{
  printf("sizeof(smb_hdr) <- %u\n", sizeof(smb_hdr));
  assert(32 == sizeof(smb_hdr));
  printf("sizeof(smb_mailslot) <- %u\n", sizeof(smb_mailslot));
  assert(8 == sizeof(smb_mailslot));
  printf("sizeof(smb_trans_req) <- %u\n", sizeof(smb_trans_req));
  assert(38 == sizeof(smb_trans_req));
  assert(1 == offsetof(smb_trans_req, totalparam));
  return 1;
}

#ifdef TEST

static char Sample[] =
"\xffSMB\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x44\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x44\x00V\x00\x03\x00\x01\x00\x00\x00\x02\x00U\x00\\MAILSLOT\\BROWSE\x00\x0f\x00\x80\xfc\x0a\x00PC785018295244\x00\x00\x05\x01\x03\x10\x05\x00\x0f\x01U\xaathe\x20madwomanintheattic's\x20memory\x20""box\x00";

static void test(void)
{
  parse_frame f = { PROT_SMB, sizeof Sample - 1, Sample, NULL };
  size_t bytes;
  printf("Sample(%u bytes):", (unsigned)f.len);
  dump_chars(Sample, f.len, stdout);
  fputc('\n', stdout);
  bytes = smb_parse(f.off, f.len, &f, NULL);
  printf("Consumed(%u bytes):", (unsigned)bytes);
  dump_chars(Sample, bytes, stdout);
  fputc('\n', stdout);
  dump(&f, 0, stdout);
}

int main(void)
{
  (void)smb_init();
  test();
  return 0;
}
#endif

