/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */

#ifndef HINT_H
#define HINT_H

/**
 * types of hints
 */
enum Hint {
	Hint_None,
	Hint_Hardware,
	Hint_OS,
	Hint_App,
	Hint_COUNT
};

/**
 * 
 */
struct hint {
	enum Hint     type;
	const char   *uniqid;   /* uniq */
	long          strength; /* numeric strength */
  const char   *tostr;    /* string representation for storing in db */
  struct hint  *next;     /* for use in list */
};
typedef struct hint hint;

#endif

