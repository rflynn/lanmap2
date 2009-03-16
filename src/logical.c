/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Logical capture frames directly from libpcap
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "env.h"
#include "types.h"
#include "prot.h"
#include "ieee802_3.h"
#include "ipv4.h"
#include "logical.h"

static size_t dump(const parse_frame *, int options, FILE *);

/**
 * exported interface
 */
const prot_iface Iface_Logical = {
  DINIT(id,           PROT_LOGICAL),
  DINIT(osi,          OSI_Phys),
  DINIT(shortname,    "Logical"),
  DINIT(propername,   "Logical"),
  DINIT(init,         NULL),
  DINIT(unload,       NULL),
  DINIT(parse,        NULL),
  DINIT(dump,         dump),
  DINIT(addr_type,    ""),
  DINIT(addr_from,    NULL),
  DINIT(addr_to,      NULL),
  DINIT(addr_format,  NULL),
  DINIT(addr_local,   NULL),
  DINIT(parents,      0),
  DINIT(parent,       NULL)
};

size_t dump(const parse_frame *f, int options, FILE *out)
{
  const logical_frame *lf = (logical_frame *)f->off;
  int bytes = fprintf(out,
    "%s id=%lu type=%lu bytes=%lu when=%lu\n",
    Iface_Logical.shortname,
    (unsigned long)lf->id,
    (unsigned long)lf->type,
    (unsigned long)lf->bytes,
    (unsigned long)lf->when);
  return (size_t)bytes;
}

#ifdef TEST
int main(void)
{
  return 0;
}
#endif

