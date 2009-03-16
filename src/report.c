/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 */
/*
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sqlite3.h>
#include "util.h"
#include "report.h"

static const char DbFile[] = "../db/db";
static sqlite3 *DB;
static sqlite3_stmt *AddrUpd,
                    *AddrIns,
                    *HintUpd,
                    *HintIns,
                    *TrafUpd,
                    *TrafIns;

int rep_init(FILE *out)
{
  int rc = sqlite3_open(DbFile, &DB);
  if (rc) {
    fprintf(out, "Can't open database: %s\n", sqlite3_errmsg(DB));
    sqlite3_close(DB);
    exit(EXIT_FAILURE);
  }

  /* Addr */
  rc = sqlite3_prepare_v2(DB,
    "UPDATE addr SET latest=DATETIME('NOW','LOCALTIME') WHERE "
    "fromtype=?1 AND from_=?2 AND totype=?3 AND to_=?4 AND reason=?5",
    -1, &AddrUpd, NULL);
  if (SQLITE_OK != rc) {
    fprintf(out, "AddrUpd prepare failed: %s\n", sqlite3_errmsg(DB));
    sqlite3_close(DB);
    exit(EXIT_FAILURE);
  }
  assert(AddrUpd);
  rc = sqlite3_prepare_v2(DB,
    "INSERT INTO addr (fromtype,from_,totype,to_,reason,weight,earliest,latest)"
    "VALUES(?1,?2,?3,?4,?5,?6,DATETIME('NOW','LOCALTIME'),DATETIME('NOW','LOCALTIME'))",
    -1, &AddrIns, NULL);
  if (SQLITE_OK != rc) {
    fprintf(out, "AddrIns prepare failed: %s\n", sqlite3_errmsg(DB));
    sqlite3_close(DB);
    exit(EXIT_FAILURE);
  }
  assert(AddrIns);

  /* Hint */
  rc = sqlite3_prepare_v2(DB,
    "UPDATE hint SET latest=DATETIME('NOW','LOCALTIME') WHERE "
    "addrtype=?1 AND addr=?2 AND hintsrc=?3 AND contents=?4",
    -1, &HintUpd, NULL);
  if (SQLITE_OK != rc) {
    fprintf(out, "HintUpd prepare failed: %s\n", sqlite3_errmsg(DB));
    sqlite3_close(DB);
    exit(EXIT_FAILURE);
  }
  assert(HintUpd);
  rc = sqlite3_prepare_v2(DB,
    "INSERT INTO hint (addrtype,addr,hintsrc,contents,earliest,latest)"
    "VALUES(?1,?2,?3,?4,DATETIME('NOW','LOCALTIME'),DATETIME('NOW','LOCALTIME'))",
    -1, &HintIns, NULL);
  if (SQLITE_OK != rc) {
    fprintf(out, "HintIns prepare failed: %s\n", sqlite3_errmsg(DB));
    sqlite3_close(DB);
    exit(EXIT_FAILURE);
  }
  assert(HintIns);

  /* Traffic */
  rc = sqlite3_prepare_v2(DB,
    "UPDATE traffic "
    "SET "
    "bytes=bytes+?1,"
    "bytes_encap=bytes_encap+?2,"
    "counter=counter+?3,"
    "latest=DATETIME('NOW','LOCALTIME') "
    "WHERE "
    "fromtype=?4 AND from_=?5 AND "
    "totype=?6 AND to_=?7 AND "
    "protocol=?8",
    -1, &TrafUpd, NULL);
  if (SQLITE_OK != rc) {
    fprintf(out, "TrafUpd prepare failed: %s\n", sqlite3_errmsg(DB));
    sqlite3_close(DB);
    exit(EXIT_FAILURE);
  }
  assert(TrafUpd);
  rc = sqlite3_prepare_v2(DB,
    "INSERT INTO traffic ("
    "fromtype,from_,totype,to_,protocol,bytes,bytes_encap,counter,earliest,latest"
    ")VALUES("
    "?1,?2,?3,?4,?5,?6,?7,?8,DATETIME('NOW','LOCALTIME'),DATETIME('NOW','LOCALTIME'))",
    -1, &TrafIns, NULL);
  if (SQLITE_OK != rc) {
    fprintf(out, "TrafIns prepare failed: %s\n", sqlite3_errmsg(DB));
    sqlite3_close(DB);
    exit(EXIT_FAILURE);
  }
  assert(TrafIns);

  printf("rep_init OK\n");
  return 1;
}


static struct timeval Runtime[2];

static void STARTTIME(void)
{
  gettimeofday(Runtime, NULL);
}

static void ENDTIME(const char *func)
{
  double d[2], secs;
  gettimeofday(Runtime + 1, NULL);
  d[0] = (Runtime[0].tv_sec * 1000000) + Runtime[0].tv_usec;
  d[1] = (Runtime[1].tv_sec * 1000000) + Runtime[1].tv_usec;
  secs = (d[1] - d[0]) / 1000000;
  printf("%s %.3f secs\n", func, secs);
}

/**
 * report a mapping between addresses as determined by some protocols
 */
void rep_addr(const char *fromtype,
              const char *from,
              const char *totype,
              const char *to,
              const char *reason,
              int weight)
{
  STARTTIME();
#ifndef TEST
  /* bind params */
  if (SQLITE_OK != sqlite3_bind_text(AddrUpd, 1, fromtype, -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(AddrUpd, 2, from,     -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(AddrUpd, 3, totype,   -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(AddrUpd, 4, to,       -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(AddrUpd, 5, reason,   -1, SQLITE_STATIC)
  ) {
    fprintf(stderr, "%s AddrUpd bind failed: %s\n", __func__, sqlite3_errmsg(DB));
  } else {
    /* update */
    if (SQLITE_DONE == sqlite3_step(AddrUpd)) {
      printf("%s AddrUpd SQLITE_DONE\n", __func__);
    } else {
      fprintf(stderr, "%s AddrUpd step failed: %s\n", __func__, sqlite3_errmsg(DB));
    }
    if (0 == sqlite3_changes(DB)) {
      /* if update doesn't update anything it means the approrpriate record hasn't
       * been created yet (which will obviously happen exactly once per unique
       * record), but since the vast majority of reports are duplicates we call
       * update first. so, let's create the record. */
      if (SQLITE_OK != sqlite3_bind_text(AddrIns, 1, fromtype, -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(AddrIns, 2, from,     -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(AddrIns, 3, totype,   -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(AddrIns, 4, to,       -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(AddrIns, 5, reason,   -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_int (AddrIns, 6, weight)
      ) {
        fprintf(stderr, "%s AddrIns bind failed: %s\n", __func__, sqlite3_errmsg(DB));
      } else {
          if (SQLITE_DONE == sqlite3_step(AddrIns)) {
          printf("%s AddrIns SQLITE_DONE\n", __func__);
        } else {
          fprintf(stderr, "%s AddrIns step failed: %s\n", __func__, sqlite3_errmsg(DB));
          goto cleanup_ins;
        }
      }
cleanup_ins:
      sqlite3_reset(AddrIns);
      sqlite3_clear_bindings(AddrIns);
    }
  }
cleanup_upd:
  sqlite3_reset(AddrUpd);
  sqlite3_clear_bindings(AddrUpd);
#endif
  ENDTIME(__func__);
}


/**
 * report a mapping between addresses as determined by some protocols
 */
void rep_hint(const char *addrtype,
              const char *addr,
              const char *hintsrc,
              const char *contents,
              int         contentlen)
{
  STARTTIME();
#ifndef TEST
  /* bind params */
  if (SQLITE_OK != sqlite3_bind_text(HintUpd, 1, addrtype, -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(HintUpd, 2, addr,     -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(HintUpd, 3, hintsrc,  -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(HintUpd, 4, contents, contentlen, SQLITE_STATIC)
  ) {
    fprintf(stderr, "%s HintUpd bind failed: %s\n", __func__, sqlite3_errmsg(DB));
  } else {
    /* update */
    if (SQLITE_DONE == sqlite3_step(HintUpd)) {
      printf("%s HintUpd SQLITE_DONE\n", __func__);
    } else {
      fprintf(stderr, "%s HintUpd step failed: %s\n", __func__, sqlite3_errmsg(DB));
    }
    if (0 == sqlite3_changes(DB)) {
      /* if update doesn't update anything it means the approrpriate record hasn't
       * been created yet (which will obviously happen exactly once per unique
       * record), but since the vast majority of reports are duplicates we call
       * update first. so, let's create the record. */
      if (SQLITE_OK != sqlite3_bind_text(HintIns, 1, addrtype, -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(HintIns, 2, addr,     -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(HintIns, 3, hintsrc,  -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(HintIns, 4, contents, contentlen, SQLITE_STATIC)
      ) {
        fprintf(stderr, "%s HintIns bind failed: %s\n", __func__, sqlite3_errmsg(DB));
      } else {
          if (SQLITE_DONE == sqlite3_step(HintIns)) {
          printf("%s HintIns SQLITE_DONE\n", __func__);
        } else {
          fprintf(stderr, "%s HintIns step failed: %s\n", __func__, sqlite3_errmsg(DB));
          goto cleanup_ins;
        }
      }
cleanup_ins:
      sqlite3_reset(HintIns);
      sqlite3_clear_bindings(HintIns);
    }
  }
cleanup_upd:
  sqlite3_reset(HintUpd);
  sqlite3_clear_bindings(HintUpd);
#endif
  ENDTIME(__func__);
}

struct traf {
  char          fromtype[16],
                from[48],
                totype[16],
                to[48],
                protocol[16];
  unsigned      counter;
  unsigned long bytes,
                bytes_encap;
};

struct traf_ptr {
  const char * const fromtype;
  const char        *from;
  const char * const totype;
  const char        *to;
  const char        *protocol;
  unsigned long      bytes;
  unsigned long      bytes_encap;
};

static struct traf TrafCache[128];
static unsigned TrafCacheLen = 0, /* number of entries */
                TrafCacheUpdates = 0; /* total number of cached entries */

static int traf_cmp(const struct traf *a, const struct traf_ptr *b)
{
  int cmp = a->to[0] - b->to[0];
  if (0 == cmp) {
    cmp = strcmp(a->to, b->to);
    if (0 == cmp) {
      cmp = strcmp(a->from, b->from);
      if (0 == cmp)
        cmp = strcmp(a->protocol, b->protocol);
    }
  }
  return cmp;
}

static void traf_cache(const struct traf_ptr *t)
{
  /* find slot */ 
  unsigned i;
  for (i = 0; i < TrafCacheLen; i++)
    if (0 == traf_cmp(TrafCache+i, t))
      break;
  if (i < TrafCacheLen) {
    /* found; update existing */
    TrafCacheUpdates++;
    TrafCache[i].counter++;
    TrafCache[i].bytes += t->bytes;
    TrafCache[i].bytes_encap += t->bytes_encap;
  } else if (i == TrafCacheLen) {
    /* not found */
    if (i < sizeof TrafCache / sizeof TrafCache[0]) {
      /* space in the cache for a new entry */
      TrafCacheLen++;
      TrafCacheUpdates++;
      strlcpy(TrafCache[i].fromtype,  t->fromtype,  sizeof TrafCache[i].fromtype);
      strlcpy(TrafCache[i].from,      t->from,      sizeof TrafCache[i].from);
      strlcpy(TrafCache[i].totype,    t->totype,    sizeof TrafCache[i].totype);
      strlcpy(TrafCache[i].to,        t->to,        sizeof TrafCache[i].to);
      strlcpy(TrafCache[i].protocol,  t->protocol,  sizeof TrafCache[i].protocol);
      TrafCache[i].counter = 1;
      TrafCache[i].bytes = t->bytes;
      TrafCache[i].bytes_encap = t->bytes_encap;
    } else {
      /* no space in the cache */
      fprintf(stderr, "!!!!!!!!!!!!!!!!!!!! CACHE FULL !!!!!!!!!!!!\n");
    }
  }
}

static void traf_commit(const struct traf *t)
{
#ifndef TEST
  /* bind params */
  if (SQLITE_OK != sqlite3_bind_int (TrafUpd, 1, t->bytes)
   || SQLITE_OK != sqlite3_bind_int (TrafUpd, 2, t->bytes_encap)
   || SQLITE_OK != sqlite3_bind_int (TrafUpd, 3, t->counter)
   || SQLITE_OK != sqlite3_bind_text(TrafUpd, 4, t->fromtype,-1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(TrafUpd, 5, t->from,    -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(TrafUpd, 6, t->totype,  -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(TrafUpd, 7, t->to,      -1, SQLITE_STATIC)
   || SQLITE_OK != sqlite3_bind_text(TrafUpd, 8, t->protocol,-1, SQLITE_STATIC)
  ) {
    fprintf(stderr, "%s TrafUpd bind failed: %s\n", __func__, sqlite3_errmsg(DB));
  } else {
    /* update */
    if (SQLITE_DONE == sqlite3_step(TrafUpd)) {
      printf("%s TrafUpd SQLITE_DONE\n", __func__);
    } else {
      fprintf(stderr, "%s TrafUpd step failed: %s\n", __func__, sqlite3_errmsg(DB));
    }
    if (0 == sqlite3_changes(DB)) {
      /* no updates?! insert a record instead */
      if (SQLITE_OK != sqlite3_bind_text(TrafIns, 1, t->fromtype,-1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(TrafIns, 2, t->from,    -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(TrafIns, 3, t->totype,  -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(TrafIns, 4, t->to,      -1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_text(TrafIns, 5, t->protocol,-1, SQLITE_STATIC)
       || SQLITE_OK != sqlite3_bind_int (TrafIns, 6, t->bytes)
       || SQLITE_OK != sqlite3_bind_int (TrafIns, 7, t->bytes_encap)
       || SQLITE_OK != sqlite3_bind_int (TrafIns, 8, t->counter)
      ) {
        fprintf(stderr, "%s TrafIns bind failed: %s\n", __func__, sqlite3_errmsg(DB));
      } else {
          if (SQLITE_DONE == sqlite3_step(TrafIns)) {
          printf("%s TrafIns SQLITE_DONE\n", __func__);
        } else {
          fprintf(stderr, "%s TrafIns step failed: %s\n", __func__, sqlite3_errmsg(DB));
          goto cleanup_ins;
        }
      }
cleanup_ins:
      sqlite3_reset(TrafIns);
      sqlite3_clear_bindings(TrafIns);
    }
  }
cleanup_upd:
  sqlite3_reset(TrafUpd);
  sqlite3_clear_bindings(TrafUpd);
#endif
}

static void traf_flush(void)
{
  unsigned i;
  STARTTIME();
  printf(">>>>>>>>>>>>>> Flushing TrafCache %u/%u\n", TrafCacheLen, TrafCacheUpdates);
  for (i = 0; i < TrafCacheLen; i++) {
    traf_commit(TrafCache+i);
  }
  TrafCacheLen = 0;
  TrafCacheUpdates = 0;
  ENDTIME(__func__);
}

/**
 * report traffic between two local hosts
 */
void rep_traf(const char * const fromtype,
              const char *from,
              const char * const totype,
              const char *to,
              const char *protocol,
              unsigned long bytes,
              unsigned long bytes_encap)
{
  static int wtf = 0;
  struct traf_ptr t = {
    fromtype, from,
    totype, to,
    protocol, bytes, bytes_encap
  };
  assert(0 != strncmp(to, "01:00:5e:", 9) && "wtf?!");
#if 0
  printf("rep_traf from=%s to=%s prot=%s bytes=%lu encap=%lu\n",
    from, to, protocol, bytes, bytes_encap);
#endif
  traf_cache(&t);
  wtf++;
  if (100 == wtf) {
    traf_flush();
    wtf = 0;
  }
}

