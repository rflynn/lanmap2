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
#include <stddef.h>
#include "util.h"
#include "env.h"
#include "prot.h"

static size_t dump(const parse_frame *, int, FILE *);

const prot_iface Iface_Trailing = {
  DINIT(id,           PROT_TRAILING),
  DINIT(osi,          OSI_Other),
  DINIT(shortname,    "Trailing"),
  DINIT(propername,   "Trailing"),
  DINIT(init,         NULL),
  DINIT(unload,       NULL),
  DINIT(parse,        NULL),
  DINIT(dump,         dump),
  DINIT(addr_type,    NULL),
  DINIT(addr_from,    NULL),
  DINIT(addr_to,      NULL),
  DINIT(addr_format,  NULL),
  DINIT(addr_local,   NULL),
  DINIT(parents,      0),
  DINIT(parent,       NULL)
};

static size_t dump(const parse_frame *f, int opt, FILE *out)
{
  const char *c = f->off;
  size_t len = f->len;
  int bytes = fprintf(out, "%s bytes=%lu ",
    Iface_Trailing.shortname, (unsigned long)len);
  bytes += dump_chars(c, len, out);
  fputc('\n', out);
  bytes++;
#if 0
  /* try and find non-junk, non-padding data that is unparsed */
  assert(
    (f->len < 32 || allzeroes(c, f->len) || allones(c, f->len)) &&
    "Help find unparsed protocols");
#endif
  return (size_t)bytes;
}



