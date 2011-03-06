/* ex: set ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 */
/*
 * Parse the XX-XX-XX CORPNAME pattern for each OUI entry and
 * produce SQL for sqlite3
 *
 * Usage: cat oui.txt | ./oui2insert | sqlite3 db
 */

#include <stdio.h>
#include <string.h>

/**
 * replace all ' with ''
 */
static void escape(char *wr, size_t wrlen, const char *rd, size_t rdlen)
{
  while (rdlen-- && wrlen-- > 1) {
    *wr++ = *rd;
    if ('\'' == *rd)
      *wr++ = '\'', wrlen--;
    rd++;
  }
  *wr = '\0';
}

int main(int argc, char *argv[])
{
  char line[1024];
  printf("BEGIN TRANSACTION;\n");
  while (NULL != fgets(line, sizeof line, stdin)) {
    char corp[64],
         corpesc[sizeof corp * 2]; /* must be 2x to account for ecapes */
    unsigned h[3];
    int cnt = sscanf(line, "%02x-%02x-%02x (hex) %63[^\r\n]\n", h+0, h+1, h+2, corp);
    if (4 == cnt) {
      escape(corpesc, sizeof corpesc, corp, strlen(corp));
      printf("INSERT OR IGNORE INTO oui VALUES('%02x:%02x:%02x','%s');\n", h[0], h[1], h[2], corpesc);
    }
  }
  printf("COMMIT;\n");
  return 0;
}

