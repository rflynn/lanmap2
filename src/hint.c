/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static int hint_cmp(const void *, const void *);

/**
 * list of all hints
 */
static hint *Hint = NULL;
static long Hints = 0;

long hints_add(const hint *h, long cnt)
{
  if (cnt > 0) {
    long alloc = Hints + cnt;
    void *tmp = realloc(Hint, alloc * sizeof *Hint);
    assert(tmp);
    Hint = tmp;
    memcpy(Hint+Hints, h, sizeof *h * cnt);
    Hints = alloc;
  }
  return cnt;
}

static int hints_sort(void)
{
  assert(NULL != Hint);
  qsort(Hint, Hints, sizeof Hints[0], hint_cmp);
}

/**
 * qsort() and bsearch() callback
 */
static int hint_cmp(const void *va, const void *vb)
{
  const hint *a = va,
             *b = vb;
  int cmp = a->type - b->type;
  if (0 == cmp) {
    cmp = a->key[0] - b->key[0];
    if (0 == cmp)
      cmp = strcmp(a->key, b->key);
  }
  return cmp;
}

