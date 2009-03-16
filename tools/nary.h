/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * a generic n-ary tree structure for use with our os and application trees
 */

#ifndef NARY_H
#define NARY_H

struct nary {
  const char  *key;
  void        *val;
  struct nary *parent,  /* single parent node */
              *child,   /* child list */
              *prev,
              *next;    /* sibling list */
};
typedef struct nary nary;

nary * nary_new(const char *key, void *val);
void   nary_init(nary *n, const char *key, void *val);
nary * nary_search(const nary *n, const char *key);
int 	 nary_insert(nary **tree, nary *node, const char *parent_key);
void   nary_map(nary *tree, void (*f)(nary *, int depth));
nary * nary_ancestor(const nary *a, const nary *b);
void 	 nary_dump(nary *n);

#endif

