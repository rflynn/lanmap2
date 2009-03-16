/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2009 Ryan Flynn
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nary.h"
#include "util.h"
#include "os.h"
#include "csvread.h"

#define LINELEN    1024
#define FIELDSMAX     8 

static nary *Tree = NULL;

static char * xstrdup(const char *s)
{
  char *x = malloc(strlen(s) + 1);
  strcpy(x, s);
  return x;
}

static os * os_new(const char *id, const char *name)
{
  os *o = malloc(sizeof *o);
  strlcpy(o->id, id, sizeof o->id);
  strlcpy(o->name, name, sizeof o->name);
  o->weight = 0;
  return o;
}

static void os_dump(nary *n, int depth)
{
  static const char Indent[] = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++";
  const os *o = n->val;
  printf("%.*s %s (%ld)\n",
    depth, Indent, n->key, (long)o->weight);
}

static void os_clear(nary *n, int depth)
{
  os *o = n->val;
  free(o);
  n->val = NULL;
}

/**
 * apply a weight adjustment on a node and all its subnodes, until
 * we find a node that matches "stop"
 */
static void do_os_weight_apply(nary *n, const char *stop, s32 weight)
{
  os *o = n->val;
  o->weight += weight;
  if (0 != strcmp(stop, n->key)) {
    if (n->child)
      do_os_weight_apply(n->child, stop, weight);
    if (n->next)
      do_os_weight_apply(n->next, stop, weight);
  }
}

/**
 * add 'weight' to all OSes between 'start' and 'stop' keys
 */
void os_weight_apply(nary *tree, const char *start, const char *stop, s32 weight)
{
  nary *n = nary_search(tree, start);
  if (n)
    do_os_weight_apply(n, stop, weight);
}

/**
 * reset all OS weight to zero
 */
static void os_weight_clear(nary *n, int depth)
{
  os *o = n->val;
  o->weight = 0;
}

struct heaviest {
  os *o;
  int depth;
};

static void do_os_heaviest(const nary *n, int depth, struct heaviest *h)
{
  os *o = n->val;
  if (o->weight > h->o->weight || (o->weight == h->o->weight && depth < h->depth)) {
    h->o = o;
    h->depth = depth;
  }
  if (n->child)
    do_os_heaviest(n->child, depth+1, h);
  if (n->next)
    do_os_heaviest(n->next, depth, h);
}

/**
 * calculate the highest-weighted OS, based on the 'weight' property and
 * also the depth of the node; the higher the depth the more specific the OS
 * version, so lower depth is a more general guess (i.e. if "FooOS" and "FooOS 3.5"
 * both have the same weight, we want to return "FooOS").
 */
static os * os_heaviest(const nary *n)
{
  struct heaviest h;
  h.o = n->val;
  h.depth = 0;
  do_os_heaviest(n, 0, &h);
  return h.o;
}

int main(int argc, char *argv[])
{
  if (argc != 2) {
    fprintf(stderr, "Usage: os-graph [path-to-os-def.csv-file]\n");
    exit(EXIT_FAILURE);
  }
  {
    FILE *f = fopen(argv[1], "r");
    if (NULL == f) {
      perror("fopen");
      exit(EXIT_FAILURE);
    }
    {
      csvread csv;
      if (!csvread_init(&csv, LINELEN, FIELDSMAX)) {
        fprintf(stderr, "csvread_init failed\n");
        exit(EXIT_FAILURE);
      }
      csvread_settrim(&csv, 1);
      {
        nary *n;
        const char *parent;
        long fields;
        while ((fields = csvread_line(&csv, f)) > 0 || !feof(f)) {
          os *o;
          if (4 != fields) {
            if (!csvread_is_comment(&csv) && !csvread_is_empty(&csv))
              fprintf(stderr, "not 4 fields: %s", csv.line);
            continue;
          }
          o = os_new(csvread_strdup(&csv, 0),
                     csvread_strdup(&csv, 1));
          parent = csvread_strdup(&csv, 2);
          n = nary_new(o->id, o);
#if 0
          printf("insert key=\"%s\" parent=\"%s\"\n", o->id, parent);
#endif
          if (!nary_insert(&Tree, n, parent))
          {
            nary_dump(Tree);
            assert(0 && "shit!");
          }
        }
      }
      csvread_destroy(&csv);
    }
    fclose(f);
  }
  if (Tree) {
    os *heavy;
    os_weight_apply(Tree, "NetBSD", "", +1);
    os_weight_apply(Tree, "OpenBSD", "", +1);
    os_weight_apply(Tree, "OpenBSD3.x", "", +1);
      nary_map(Tree, os_dump);
    heavy = os_heaviest(Tree);
    printf("heaviest=%s (%ld)\n", heavy->id, (long)heavy->weight);
  } else {
    printf("no entries!\n");
  }
  return 0;
}

