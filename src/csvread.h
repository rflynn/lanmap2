/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 *
 * a line-based csv parser.
 * DOES NOT HANDLE MULT-LINE DATA
 */

#ifndef CSVREAD_H
#define CSVREAD_H

typedef struct csvread csvread;
struct csvread {
  long      linebufsz;
  char     *line;
  long      fieldsmax,
            fields;
  char    **field;
  size_t   *fieldlen;
  unsigned  trim:1;
};

#define csvread_nth(c, n)     ((c)->field[n])
/* it's non-standard behavior to trim fields, so we'll make
 * it optional */
#define csvread_settrim(c, n) ((c)->trim = !!(n))

int    csvread_init   (csvread *, long linebufsz, long fieldsmax);
void   csvread_destroy(csvread *);
long   csvread_line   (csvread *, FILE *);
char * csvread_strdup (csvread *, unsigned nth);
int    csvread_is_comment(const csvread *);
int    csvread_is_empty  (const csvread *);

#endif

