/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 *
 * a line-based csv parser.
 * DOES NOT HANDLE MULT-LINE DATA
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h> /* malloc */
#include <string.h>
#include <ctype.h>
#include "csvread.h"

/**
 * initialize limits and allocate memory
 */
int csvread_init(csvread *r, long linebufsz, long fieldsmax)
{
  int ok = 0;
  r->trim = 0;
  r->fields = 0L;
  r->linebufsz = linebufsz;
  r->fieldsmax = fieldsmax;
  r->line = malloc(linebufsz * sizeof r->line[0]);
  if (r->line) {
    r->field = malloc(fieldsmax * sizeof r->field[0]);
    if (r->field) {
      r->fieldlen = malloc(fieldsmax * sizeof r->fieldlen[0]);
      if (r->fieldlen) {
        ok = 1;
      } else {
        free(r->field);
        r->field = NULL;
        free(r->line);
        r->line = NULL;
      }
    } else {
      free(r->line);
      r->line = NULL;
    }
  }
  return ok;
}

/**
 * de-allocate all memory
 */
void csvread_destroy(csvread *r)
{
  r->linebufsz = 0L;
  free(r->line);
  r->line = NULL;
  r->fieldsmax = 0L;
  r->fields = 0L;
  free(r->field);
  r->field = NULL;
}

/**
 * separate a single line into its constituent fields.
 * honor quoted commas.
 * populate r->fieldcnt, r->field and r->fieldlen
 */
static void splitfields(csvread *r)
{
  unsigned i = 0;
  int esc = 0;
  r->field[0] = r->line;
  while ('\0' != r->line[i]) {
    switch (r->line[i]) {
    case '"':
      esc = !esc;
      break;
    case ',':
      if (!esc) {
        r->fieldlen[r->fields] = r->line + i - r->field[r->fields];
#if 0
        printf("%s i=%u len[%ld]=%u\n",
          __func__, i, r->fields, (unsigned)r->fieldlen[r->fields]);
#endif
        r->fields++;
        if (r->fields == r->fieldsmax)
          goto done;
        r->field[r->fields] = r->line+i+1;
      }
      break;
    default: /* do nothing */
      break;
    }
    i++;
  }
  r->fieldlen[r->fields] = r->line + i - r->field[r->fields] - 1;
  r->fields++;
done:
  0; /* can't have label at the end of a function */
}

/**
 * remove embedded quotes
 */
static void dequot(csvread *r)
{
  long i;
  for (i = 0L; i < r->fields; i++)
  {
    unsigned rd = 0,
             wr = 0;
#if 0
    printf("%s before len[%ld]=%u\n", __func__, i, (unsigned)r->fieldlen[i]);
#endif
    if ('"' == r->field[i][0] && '"' == r->field[i][r->fieldlen[i]-1]) {
      /* quoted string */
      r->fieldlen[i] -= 2;
      r->field[i]++;
    }
    while (rd < r->fieldlen[i]) {
      if ('"' == r->field[i][rd])
        rd++; /* assume all inside quotes are doubled-up */
      r->field[i][wr++] = r->field[i][rd++];
    }
    r->fieldlen[i] -= rd - wr; /* subtract for any overwritten shit */
#if 0
    printf("%s before len[%ld]=%u\n", __func__, i, (unsigned)r->fieldlen[i]);
#endif
  }
}

static size_t trim(char **field, size_t len)
{
  size_t i = 0,
         l = len;
  if (len) {
    while (l && isspace((int)(*field)[--l]))
      ;
    l++;
    while (i < l && isspace((int)(*field)[i]))
      i++;
    if (i) {
      *field += i;
      l -= i;
    }
  }
  return l;
}

static void trimfields(csvread *r)
{
  long i;
  for (i = 0; i < r->fields; i++)
    r->fieldlen[i] = trim(&r->field[i], r->fieldlen[i]);
}

/**
 * @return -1 for error/feof; otherwise number of fields in line; 0 for comments, empty lines
 * @note currently does not support multi-line fields
 */
long csvread_line(csvread *r, FILE *f)
{
  char *line;
  long fieldcnt = -1;
  r->fields = 0L;
  line = fgets(r->line, r->linebufsz, f);
  if (line) {
    strcspn(r->line, "\n")[r->line] = '\0'; /* remove newline */
    if ('#' == r->line[0]) {
      /* comment */
      fieldcnt = 0L;
    } else if ('\r' == r->line[0] || '\n' == r->line[0]) {
      /* empty line */
      fieldcnt = 0L;
    } else {
      splitfields(r);
      dequot(r);
      fieldcnt = r->fields;
      if (r->trim)
        trimfields(r);
    }
  }
  return fieldcnt;
}

char * csvread_strdup(csvread *c, unsigned nth)
{
  char *s = malloc(c->fieldlen[nth] + 1);
  memcpy(s, c->field[nth], c->fieldlen[nth]);
  s[c->fieldlen[nth]] = '\0';
  return s;
}

/**
 * just for testing
 */
static void csvread_dump(const csvread *r)
{
  long i;
  printf("csvread(%p):\n", (void *)r);
  printf(" linebufsz=%ld\n", r->linebufsz);
  printf(" line={%s}\n", r->line);
  printf(" fieldsmax=%ld\n", r->fieldsmax);
  printf(" fields=%ld\n", r->fields);
  printf(" field=[");
  for (i = 0L; i < r->fields; i++)
    printf(" (%u){%.*s}",
      (unsigned)r->fieldlen[i], 
      (unsigned)r->fieldlen[i], r->field[i]);
  printf(" ]\n");
}

int csvread_is_comment(const csvread *c)
{
  return '#' == c->line[0];
}

int csvread_is_empty(const csvread *c)
{
  return '\r' == c->line[0]
      || '\n' == c->line[0];
}

#ifdef TEST

static void test_init(void)
{
  csvread c;
  csvread_init(&c, 1024, 16);
  csvread_destroy(&c);
}

static void test_toomanyfields(void)
{
  csvread c;
  csvread_init(&c, 1024, 1);
  strcpy(c.line, ",");
  splitfields(&c);
  csvread_dump(&c);
  csvread_destroy(&c);
}

static void test_abc(void)
{
  csvread c;
  csvread_init(&c, 1024, 16);
  strcpy(c.line, "a,b,c");
  splitfields(&c);
  csvread_dump(&c);
  csvread_destroy(&c);
}

static void test_emptyfields(void)
{
  csvread c;
  csvread_init(&c, 1024, 16);
  strcpy(c.line, ",");
  splitfields(&c);
  csvread_dump(&c);
  csvread_destroy(&c);
}

static void test_emptystring(void)
{
  csvread c;
  csvread_init(&c, 1024, 16);
  strcpy(c.line, "\"\"");
  splitfields(&c);
  dequot(&c);
  csvread_dump(&c);
  csvread_destroy(&c);
}

static void test_quotedcomma(void)
{
  csvread c;
  csvread_init(&c, 1024, 1);
  strcpy(c.line, "\",\"");
  splitfields(&c);
  dequot(&c);
  csvread_dump(&c);
  csvread_destroy(&c);
}

static void test_quotedcommas(void)
{
  csvread c;
  csvread_init(&c, 1024, 2);
  strcpy(c.line, "\"a,b,c\",\"d,e,f\"");
  splitfields(&c);
  dequot(&c);
  csvread_dump(&c);
  csvread_destroy(&c);
}

static void test_quotes(void)
{
  csvread c;
  csvread_init(&c, 1024, 2);
  strcpy(c.line, "\"\"foo\"\",\"oh, my \"\"god\"\"\"");
  splitfields(&c);
  dequot(&c);
  csvread_dump(&c);
  csvread_destroy(&c);
}

static void test_read_icmp_echo(void)
{
  csvread c;
  FILE *f;
  long r;
  printf("%s\n", __func__);
  csvread_init(&c, 4096, 11);
  csvread_settrim(&c, 1);
  f = fopen("../data/icmp_echo.csv", "r");
  assert(f);
  while ((r = csvread_line(&c, f)) > 0 || !feof(f)) {
    printf("csvread_line=%ld\n", r);
    csvread_dump(&c);
  }
  fclose(f);
  csvread_destroy(&c);
}

int main(void)
{
  test_init();
  test_toomanyfields();
  test_abc();
  test_emptyfields();
  test_emptystring();
  test_quotedcomma();
  test_quotedcommas();
  test_quotes();
  test_read_icmp_echo();
  return 0;
}
#endif

