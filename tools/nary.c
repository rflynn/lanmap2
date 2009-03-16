/* ex: set ff=dos ts=2 et: */
/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nary.h"

void nary_init(nary *n, const char *key, void *val)
{
  n->key = key;
  n->val = val;
  n->parent = NULL;
  n->child  = NULL;
  n->next   = NULL;
}

nary * nary_new(const char *key, void *val)
{
  nary *n = malloc(sizeof *n);
  nary_init(n, key, val);
  return n;
}

/**
 * find a nary node by key
 */
nary * nary_search(const nary *n, const char *key)
{
  nary *res = NULL;
  if (0 == strcmp(n->key, key)) {
    res = (nary *)n;
  } else if (n->next) {
    res = nary_search(n->next, key);
  }
  if (!res && n->child)
    res = nary_search(n->child, key);
  return res;
}

int nary_insert(nary **tree, nary *node, const char *parent_key)
{
  if (NULL == *tree) {
    *tree = node;
  } else {
    nary *parent = nary_search(*tree, parent_key);
    if (!parent) {
      fprintf(stderr, "could not insert node(key='%s'), parent_key='%s' not found!\n",
        node->key, parent_key);
      return 0;
    }
    node->parent = parent;
    if (NULL == parent->child) {
      parent->child = node;
    } else {
      nary *sibling = parent->child;
      while (sibling->next)
        sibling = sibling->next;
      sibling->next = node;
      node->prev = sibling;
    }
  }
  return 1;
}

static int nary_is_ancestor(const nary *n, const nary *ancestor)
{
  while (n && n != ancestor)
    n = n->parent;
  return n == ancestor;
}

/**
 * given two nodes find their most-recent common ancestor node
 * @note O(n^2) complexity; but we assume a fairly small (<100) number of ancestors each
 */
nary * nary_ancestor(const nary *a, const nary *b)
{
  while (a) {
    if (nary_is_ancestor(b, a))
      return (nary *)a;
    a = a->parent;
  }
  return NULL;
}

/**
 * apply a callback to all nodes
 */
static void do_nary_map(nary *n, int depth, void (*f)(nary *, int depth))
{
  f(n, depth);
  if (n->child)
    do_nary_map(n->child, depth+1, f);
  if (n->next)
    do_nary_map(n->next, depth, f);
}

void nary_map(nary *n, void (*f)(nary *, int depth))
{
  do_nary_map(n, 0, f);
}


static void nary_print(nary *n, int depth)
{
  static const char Indent[] = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++";
  printf("%.*s %s\n",
    depth, Indent, n->key);
}

void nary_dump(nary *n)
{
  nary_map(n, nary_print);
}


