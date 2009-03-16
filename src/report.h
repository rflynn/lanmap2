/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 */
/*
 *
 */

#ifndef REPORT_H
#define REPORT_H

int  rep_init(FILE *);

void rep_addr(const char *fromtype,
              const char *from,
              const char *totype,
              const char *to,
              const char *reason,
              int weight);

void rep_hint(const char *addrtype,
              const char *addr,
              const char *hintsrc,
              const char *contents,
              int         contentlen);

void rep_traf(const char *fromtype,
              const char *from,
              const char *totype,
              const char *to,
              const char *protocol,
              unsigned long bytes,
              unsigned long bytes_encap);

#endif

