/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 */
/*
 * handle operating system definitions
 */

#include <stdio.h>
#include "util.h"
#include "os.h"

static os *OSes = NULL;

int os_loadfile(const char *filename)
{
  csvread c;
  long fields;
  FILE *f = fopen(filename, "r");
  if (!f) {
    perror("fopen");
    return 0;
  }
  if (!csvread_init(&c)) {
    LOGF(__FILE__, __LINE__, "csvread_init failed");
    return 0;
  }
  while ((fields = csvread_line(&c, f)) > 0 || !feof(f)) {
    os o;
    if (fields != 5) {
      fprintf(stderr, "");
      continue;
    }
  }
}

