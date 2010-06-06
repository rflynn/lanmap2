/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include "util.h"

#define LOGFILE "foo.log" /* FIXME: make this configurable in some fashion */

/**
 * print various 
 */
void DEBUGF(const char *file, unsigned line, const char *fmt, ...)
{
#ifdef DEBUG
  va_list args;
  fprintf(stderr, "%s:%u ", file, line);
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
#endif
}

/**
 * print non-debug info into a logfile and to stdout if we're in DEBUG
 */
void LOGF(const char *file, unsigned line, const char *fmt, ...)
{
  FILE *f = fopen(LOGFILE, "a+");
  char when[32] = "????""-??""-??T??:??:??"; /* NOTE: split strings to avoid dreaded trigraph sequences */
  time_t t = time(NULL);
  struct tm *tm = localtime(&t);
  if (tm) {
    snprintf(when, sizeof when, "%04d-%02d-%02dT%02d:%02d:%02d",
      1900 + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
  }
  if (f) { /* print to logfile */
    va_list args;
    fprintf(f, "%s ", when);
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fclose(f);
  }
  { /* print to console */
    va_list args;
    printf("%s:%u ", file, line);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
  }
}

/**
 * Safe openbsd-style string copying. Guarentees \0.
 * @param dest destination buffer
 * @param src source string
 * @param size size of dest in bytes
 * @return copied length in bytes
 * @note use this instead of strncpy, which sucks
 */
size_t strlcpy(char *dst, const char *src, size_t size)
{
  char *orig = dst;
  /* copy the string leaving room for the zero-termination */
  size--;
  while (*src != '\0' && size-- > 0)
    *dst++ = *src++;
  *dst = '\0';
  /* If we didn't copy the whole string, report error */
  if (*src != '\0') 
    errno = -1;
  return (size_t)(dst - orig);
}

/**
 * safe OpenBSD-style string concatenation. guarentees \0
 * @param dst destination buffer
 * @param src source string
 * @param size size of destination buffer
 * @return length of new string in bytes
 */
size_t strlcat(char *dst, const char *src, size_t size)
{
  char *orig = dst;
  /* find the end of the destination */
  size--;  
  while (*dst != '\0' && size-- > 0) 
    dst++;
  if (size <= 0)
    errno = -1;
  else {
    while (*src != '\0' && size-- > 0)
      *dst++ = *src++;
    *dst = '\0';
    if (*src != '\0') 
      errno = -1;
  }
  return (size_t)(dst - orig);
}

/**
 * dump hex bytes to stdout
 * @return number of bytes written
 */
size_t dump_bytes(const char *buf, size_t len, FILE *f)
{
  size_t bytes = len * 4;
  while (len--)
    fprintf(f, "\\x%02x", (u8)*buf++);
  return bytes;
}

size_t dump_bytes_buf(char *dst, size_t dstlen, const char *buf, size_t len)
{
  size_t bytes = len;
  int used;
  while (dstlen >= 4 && len--) {
    used = snprintf(dst, dstlen, "\\x%02x", (u8)*buf++);
    if (used > 0)
      dst += used, dstlen -= used;
  }
  *dst = '\0';
  return bytes;
}

/**
 * dump ASCII chars, or hex bytes if not printable
 * @return number of bytes written
 */
size_t dump_chars(const char *buf, size_t len, FILE *f)
{
  static const char Hex[256][4] = {
    "\\x00", "\\x01", "\\x02", "\\x03", "\\x04", "\\x05", "\\x06", "\\x07",
    "\\x08", "\\x09", "\\x0a", "\\x0b", "\\x0c", "\\x0d", "\\x0e", "\\x0f",
    "\\x10", "\\x11", "\\x12", "\\x13", "\\x14", "\\x15", "\\x16", "\\x17",
    "\\x18", "\\x19", "\\x1a", "\\x1b", "\\x1c", "\\x1d", "\\x1e", "\\x1f",
    "\\x20", "\\x21", "\\x22", "\\x23", "\\x24", "\\x25", "\\x26", "\\x27",
    "\\x28", "\\x29", "\\x2a", "\\x2b", "\\x2c", "\\x2d", "\\x2e", "\\x2f",
    "\\x30", "\\x31", "\\x32", "\\x33", "\\x34", "\\x35", "\\x36", "\\x37",
    "\\x38", "\\x39", "\\x3a", "\\x3b", "\\x3c", "\\x3d", "\\x3e", "\\x3f",
    "\\x40", "\\x41", "\\x42", "\\x43", "\\x44", "\\x45", "\\x46", "\\x47",
    "\\x48", "\\x49", "\\x4a", "\\x4b", "\\x4c", "\\x4d", "\\x4e", "\\x4f",
    "\\x50", "\\x51", "\\x52", "\\x53", "\\x54", "\\x55", "\\x56", "\\x57",
    "\\x58", "\\x59", "\\x5a", "\\x5b", "\\x5c", "\\x5d", "\\x5e", "\\x5f",
    "\\x60", "\\x61", "\\x62", "\\x63", "\\x64", "\\x65", "\\x66", "\\x67",
    "\\x68", "\\x69", "\\x6a", "\\x6b", "\\x6c", "\\x6d", "\\x6e", "\\x6f",
    "\\x70", "\\x71", "\\x72", "\\x73", "\\x74", "\\x75", "\\x76", "\\x77",
    "\\x78", "\\x79", "\\x7a", "\\x7b", "\\x7c", "\\x7d", "\\x7e", "\\x7f",
    "\\x80", "\\x81", "\\x82", "\\x83", "\\x84", "\\x85", "\\x86", "\\x87",
    "\\x88", "\\x89", "\\x8a", "\\x8b", "\\x8c", "\\x8d", "\\x8e", "\\x8f",
    "\\x90", "\\x91", "\\x92", "\\x93", "\\x94", "\\x95", "\\x96", "\\x97",
    "\\x98", "\\x99", "\\x9a", "\\x9b", "\\x9c", "\\x9d", "\\x9e", "\\x9f",
    "\\xa0", "\\xa1", "\\xa2", "\\xa3", "\\xa4", "\\xa5", "\\xa6", "\\xa7",
    "\\xa8", "\\xa9", "\\xaa", "\\xab", "\\xac", "\\xad", "\\xae", "\\xaf",
    "\\xb0", "\\xb1", "\\xb2", "\\xb3", "\\xb4", "\\xb5", "\\xb6", "\\xb7",
    "\\xb8", "\\xb9", "\\xba", "\\xbb", "\\xbc", "\\xbd", "\\xbe", "\\xbf",
    "\\xc0", "\\xc1", "\\xc2", "\\xc3", "\\xc4", "\\xc5", "\\xc6", "\\xc7",
    "\\xc8", "\\xc9", "\\xca", "\\xcb", "\\xcc", "\\xcd", "\\xce", "\\xcf",
    "\\xd0", "\\xd1", "\\xd2", "\\xd3", "\\xd4", "\\xd5", "\\xd6", "\\xd7",
    "\\xd8", "\\xd9", "\\xda", "\\xdb", "\\xdc", "\\xdd", "\\xde", "\\xdf",
    "\\xe0", "\\xe1", "\\xe2", "\\xe3", "\\xe4", "\\xe5", "\\xe6", "\\xe7",
    "\\xe8", "\\xe9", "\\xea", "\\xeb", "\\xec", "\\xed", "\\xee", "\\xef",
    "\\xf0", "\\xf1", "\\xf2", "\\xf3", "\\xf4", "\\xf5", "\\xf6", "\\xf7",
    "\\xf8", "\\xf9", "\\xfa", "\\xfb", "\\xfc", "\\xfd", "\\xfe", "\\xff"
  };
  size_t bytes = len;
  setlinebuf(f);
  while (len--) {
    if ((' ' == *buf || isalnum((int)*buf) || ispunct((int)*buf)) && !(0x80 & *buf)) {
      fputc(*buf++, f);
    } else {
      fwrite(Hex[(u8)*buf++], 4, 1, f);
      bytes += 3; /* 1 byte already assumed */
    }
  }
  return bytes;
}

size_t dump_chars_buf(char *dst, size_t dstlen, const char *buf, size_t len)
{
  size_t bytes = len;
  while (dstlen >= 4 && len--) {
    if (*buf && !(0x80 & *buf) && (isalnum((int)*buf) || ispunct((int)*buf) || ' ' == *buf)) {
      *dst++ = *buf++;
      dstlen--;
    } else {
      int used = snprintf(dst, dstlen, "\\x%02x", (u8)*buf++);
      if (used > 0)
        dst += used, dstlen -= used;
    }
  }
  *dst = '\0';
  return bytes;
}

/**
 * produce a more friendly version of 'dump_chars_buf' output string; convert non-human-readable characters to '.'
 */
size_t dump_chars_buf2(char *dst, size_t dstlen, const char *buf, size_t len)
{
  size_t bytes = len;
  while (dstlen >= 4 && len--) {
    if (*buf && !(0x80 & *buf) && (isalnum((int)*buf) || ispunct((int)*buf) || ' ' == *buf)) {
      *dst++ = *buf++;
      dstlen--;
    } else {
      *dst++ = '.';
      buf++;
    }
  }
  *dst = '\0';
  return bytes;
}

/**
 * Similar to dump_bytes_buf; however, the 'buf' contents here are assumed to be
 * a single hash value such as MD5, SHA1, etc. we want it formatted as a string of
 * 2-char hex values without any leading "\x"
 */
size_t dump_hash_buf(char *dst, size_t dstlen, const u8 *buf, size_t len)
{
  size_t bytes = len;
  assert(dstlen > 2 * len && "contents of 'buf' cannot possibly fit in 'dst'!");
  while (dstlen > 2 && len--) {
    snprintf(dst, dstlen, "%02x", (u8)*buf++);
    dst += 2, dstlen -= 2;
  }
  *dst = '\0';
  return bytes;
}

/**
 * trim space chars from the end of a string
 */
char * strrtrim(char *s)
{
  size_t olen = strlen(s);
  size_t len = olen;
  while (len && isspace(s[--len]))
    ;
  if (len != olen && !isspace(s[len]))
    len++;
  if (len != olen)
    s[len] = '\0';
  return s;
}

/**
 * trim preceeding spaces
 */
char * strltrim(char *s)
{
  char *save = s;
  while (*s && isspace((int)*s))
    s++;
  if (s != save)
    memmove(save, s, strlen(s) + 1);
  return save;
}

/**
 *
 */
char * strtrim(char *s)
{
  strltrim(s);
  strrtrim(s);
  return s;
}

/**
 * trim preceeding spaces off of a binary data field
 */
size_t memltrim(char *m, size_t len)
{
  char *save = m;
  size_t l = len;
  while (l && isspace(*m))
    m++, l--;
  if (l < len) {
    len = l; /* adjust return length */
    memmove(save, m, l);
  }
  return len;
}

/*
 * consume consecutive bytes from 'm', of maximum length 'len', while cb() returns non-zero for them
 */
ptrdiff_t memmatch(const char *m, size_t len, int (*cb)(int))
{
  const char *start = m,
             *stop = m + len;
  while (m < stop && cb(*m))
    m++;
  return m - start;
}

int str_endswith(const char *str, const char *match)
{
  size_t slen = strlen(str),
         mlen = strlen(match);
  return mlen <= slen && 0 == strcmp(str+(slen-mlen), match);
}

/**
 * map ASCII hex chars to integer equivalents
 */
static const char HexTbl[256] = {
  /* low ASCII */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
  0, 10,11,12,13,14,15,0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 10,11,12,13,14,15,0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  /* high ASCII */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* convert 1 ASCII hex digit to its integer equivalent */
char hexint(const u8 hex)
{
  return HexTbl[hex];
}

/* convert 2 ASCII hex digits to their integer equivalent */
char hexint2(const u8 *hex)
{
  return (HexTbl[hex[0]] << 4) |
          HexTbl[hex[1]];
}

/* convert 3 ASCII hex digits to their integer equivalent */
unsigned hexint3(const u8 *hex)
{
  return (HexTbl[hex[0]] << 8) |
         (HexTbl[hex[1]] << 4) |
          HexTbl[hex[2]];
}

/* convert 4 ASCII hex digits to their integer equivalent */
unsigned hexint4(const u8 *hex)
{
  return (HexTbl[hex[0]] << 12) |
         (HexTbl[hex[1]] <<  8) |
         (HexTbl[hex[2]] <<  4) |
          HexTbl[hex[3]];
}

/* convert 8 ASCII hex digits to their integer equivalent */
unsigned long hexint8(const u8 *hex)
{
  return ((unsigned long)HexTbl[hex[0]] << 28) |
         ((unsigned long)HexTbl[hex[1]] << 24) |
         ((unsigned long)HexTbl[hex[2]] << 20) |
         ((unsigned long)HexTbl[hex[3]] << 16) |
         ((unsigned long)HexTbl[hex[4]] << 12) |
         ((unsigned long)HexTbl[hex[5]] <<  8) |
         ((unsigned long)HexTbl[hex[6]] <<  4) |
          (unsigned long)HexTbl[hex[7]];
}

/**
 * @return bytes written to 'dst'
 */
size_t base64enc(const char *src, size_t srclen, char *dst, size_t dstlen)
{
  static const char Enc[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz"
                              "0123456789+/";
  const char *save = dst;
  assert(srclen * 4 <= dstlen * 3 && "base64enc dest too small!");
  while (srclen >= 3) {
    *dst++ = Enc[((src[0] & 0xFC) >> 2)];
    *dst++ = Enc[((src[0] & 0x03) << 4) | ((src[1] & 0xF0) >> 4)];
    *dst++ = Enc[((src[1] & 0x0F) << 2) | ((src[2] & 0xC0) >> 6)];
    *dst++ = Enc[((src[2] & 0x3F))];
    src += 3;
    srclen -= 3;
  }
  if (srclen) {
    *dst++ = Enc[(src[0] & 0xFC) >> 2];
    if (1 == srclen) {
      *dst++ = Enc[((src[0] & 0x03) << 4)];
      *dst++ = '=';
      *dst++ = '=';
    } else if (2 == srclen) {
      *dst++ = Enc[((src[0] & 0x03) << 4) | ((src[1] & 0xF0) >> 4)];
      *dst++ = Enc[((src[1] & 0x0F) << 2)];
      *dst++ = '=';
    }
  }
  return (size_t)(dst - save);
}

/**
 * mempbrk is to strpbrk as memchr is to strchr
 * @note memstr is more convenient and generally useful
 * @note naive O(n^2) implementation; 'needle' generally <= 5 bytes and 'haystack' is usually <1K
 */
const char * mempbrk(const char *haystack,
                     const char *needle,
                          size_t haylen,
                          size_t needlen)
{
  if (needlen && needlen <= haylen) {
    const char *hayend = haystack + haylen - needlen + 1;
    size_t n;
    while (haystack < hayend) {
      n = needlen;
      while (n--)
        if (haystack[n] != needle[n])
          goto next;
      goto found;
next:
      haystack++;
    }
  }
  haystack = NULL;
found:
  return haystack;
}


/**
 * memstr is to strstr as memchr is to strchr
 */
const char * memstr(const char *haystack, const char *needle, size_t haylen)
{
  size_t needlen = strlen(needle);
  return mempbrk(haystack, (char *)needle, haylen, needlen);
}

/**
 * memnstr is to strrstr as memrchr is to strrchr
 * NOTE: naive O(n^2) implementation
 */
const char * memrstr(const char *hay, const char *need, size_t haylen)
{
  size_t nl = strlen(need);
  int i = (int)(nl - haylen);
  while (i > -1) {
    if (hay[i] == *need && 0 == memcmp(hay+i, need, nl))
      goto found;
    i--;
  }
found:
  return (i > -1 ? hay+i : NULL);
}

#define LONG_BIT 32

#define IDX(c)  ((unsigned char)(c) / LONG_BIT)
#define BIT(c)  ((unsigned long)1 << ((unsigned char)(c) % LONG_BIT))

/**
 * binary version of strspn
 */
size_t memspn(const char *mem, size_t memlen, const char *accept, size_t acceptlen)
{
  const char *m;
  unsigned long bit;
  unsigned long tbl[(UCHAR_MAX + 1) / LONG_BIT];
  unsigned idx;
  if(0 == memlen)
    return (0);
#if LONG_BIT == 64  /* better to unroll on 64-bit */
  tbl[3] = tbl[2] = tbl[1] = tbl[0] = 0;
#else
  for (idx = 0; idx < sizeof tbl / sizeof tbl[0]; idx++)
    tbl[idx] = 0;
#endif
  while (acceptlen--) {
    idx = IDX(*accept);
    bit = BIT(*accept);
    tbl[idx] |= bit;
    accept++;
  }
  for (m = mem; memlen; m++, memlen--) {
    idx = IDX(*m);
    bit = BIT(*m);
    if ((tbl[idx] & bit) == 0)
      break;
  }
  return (size_t)(m - mem);
}

/**
 * binary version of strcspn
 */
size_t memcspn(const char *mem, size_t memlen, const char *reject, size_t rejectlen)
{
  const char *m;
  unsigned long bit;
  unsigned long tbl[(UCHAR_MAX + 1) / LONG_BIT];
  unsigned idx;
  if(0 == memlen)
    return (0);
#if LONG_BIT == 64  /* better to unroll on 64-bit */
  tbl[3] = tbl[2] = tbl[1] = tbl[0] = 0;
#else
  for (idx = 0; idx < sizeof tbl / sizeof tbl[0]; idx++)
    tbl[idx] = 0;
#endif
  while (rejectlen--) {
    idx = IDX(*reject);
    bit = BIT(*reject);
    tbl[idx] |= bit;
    reject++;
  }
  for (m = mem; memlen; m++, memlen--) {
    idx = IDX(*m);
    bit = BIT(*m);
    if ((tbl[idx] & bit) != 0)
      break;
  }
  return (size_t)(m - mem);
}

void strupper(char *s, size_t len)
{
  while (len--)
    *s = toupper((int)*s), s++;
}

void strlower(char *s, size_t len)
{
  while (len--)
    *s = tolower((int)*s), s++;
}

/**
 * decode multiple lines in the following format to original binary:
 *  shortest line: "0060   34                                               41",
 *  longest line:  "0000   02 b4 6e 57 00 01 00 13 53 45 50 30 30 31 46 36  ..nW....SEP001F6\n"
 */
size_t decode_hex_dump(char *dst, size_t dstlen, const char *src, size_t srclen)
{
  char tmp[256];
  const char *odst = dst;
  size_t line = 1;
  while (dstlen > 0 && (line = strcspn(src, "\n")) > 55) {
    unsigned x[16], cnt;
    memcpy(tmp, src, line+1);
    tmp[line+1] = '\0';
    tmp[54] = '\0';
    cnt = sscanf(tmp+7, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                        x+0, x+1, x+2, x+3, x+4, x+5, x+6, x+7, x+8, x+9, x+10, x+11, x+12, x+13, x+14, x+15);
    if (cnt > 0) {
      unsigned i = 0;
      while (dstlen > 0 && i < cnt)
        *dst++ = (char)x[i++], dstlen--;
    }
    src += line + 1;
  }
  return (size_t)(dst-odst);
}

int allzeroes(const char *c, size_t len)
{
  while (len--)
    if (*c++ != 0)
      return 0;
  return 1;
}

int allones(const char *c, size_t len)
{
  while (len--)
    if ((u8)*c++ != 0xFF)
      return 0;
  return 1;
}








#ifdef TEST /* if compiled with -DTEST then run our unit tests */

static void test_memltrim(void)
{
  size_t i;
  char guineapig[8];
  size_t ret;
  static struct {
    char before[8],
                  after[8];
    size_t belen, aflen;
  } *t, Test[] = {
    { "",      "" , 0, 0 },
    { "A",     "A", 1, 1 },
    { "A ",    "A ",2, 2 },
    { " A",    "A", 2, 1 },
    { "\tA",   "A" ,2, 1 },
    { " A ",   "A ",3, 2 },
    { "  5---","5", 3, 1 },
  };
  printf("test_memltrim\n");
  for (i = 0; i < sizeof Test / sizeof Test[0]; i++) {
    t = Test + i;
    printf("[%u] \"%s\" -> \"%s\"... ", (unsigned)i, t->before, t->after);
    memcpy(guineapig, t->before, t->belen);
    ret = memltrim(guineapig, t->belen);
    if (ret == t->aflen && 0 == memcmp(guineapig, t->after, t->aflen))
      printf("OK (\"%.*s\")\n", ret, guineapig);
    else
      printf("!! (\"%.*s\")\n", ret, guineapig);
  }
}

static void test_strltrim(void)
{
  size_t i;
  char guineapig[8];
  static struct {
    char before[8],
         after[8];
  } *t, Test[] = {
    { "",   ""  },
    { "A",  "A" },
    { "A ", "A "},
    { " A", "A" },
    { "\tA","A" },
    { " A ","A "},
  };
  printf("test_strltrim\n");
  for (i = 0; i < sizeof Test / sizeof Test[0]; i++) {
    t = Test + i;
    printf("[%u] \"%s\" -> \"%s\"... ", (unsigned)i, t->before, t->after);
    strlcpy(guineapig, t->before, sizeof guineapig);
    strltrim(guineapig);
    if (0 == strcmp(guineapig, t->after))
      printf("OK (\"%s\")\n", guineapig);
    else
      printf("!! (\"%s\")\n", guineapig);
  }
}

static void test_base64enc(void)
{
  char dst[64];
  size_t dstlen, i;
  static const struct {
    const char *src;
    size_t srclen;
    const char *dst;
    size_t dstlen;
  } *t, Test[] = {
    { "",                   0,  "",             0 },
    { "\x00",               1,  "AA==",         4 },
    { "\x00\x00",           2,  "AAA=",         4 },
    { "\x00\x00\x00",       3,  "AAAA",         4 },
    { "\x00\x00\x00\x00",   4,  "AAAAAA==",     8 },
    { ".",                  1,  "Lg==",         4 },
    { "..",                 2,  "Li4=",         4 },
    { "...",                3,  "Li4u",         4 },
    { "....",               4,  "Li4uLg==",     8 },
    { "8==D",               4,  "OD09RA==",     8 },
    { "HELLO",              5,  "SEVMTE8=",     8 },
  };
  printf("%s\n", __func__);
  for (i = 0; i < sizeof Test / sizeof Test[0]; i++) {
    t = Test + i;
    printf("[%u] \"", (unsigned)i);
    dump_chars(t->src, t->srclen, stdout);
    printf("\"(%u) -> ", (unsigned)t->srclen);
    fflush(stdout);
    dstlen = base64enc((char *)t->src, t->srclen, dst, sizeof dst);
    printf("\"%.*s\"(%u) ", (unsigned)dstlen, dst, (unsigned)dstlen);
    if (dstlen == t->dstlen && 0 == memcmp(dst, t->dst, dstlen))
      printf(" [OK]\n");
    else {
      printf(" [!!] (expect \"%.*s\"(%u))\n",
        (unsigned)t->dstlen, t->dst, (unsigned)t->dstlen);
      assert(0);
    }
  }
}

static const char *OkStr[] = {
  "!!",
  "OK"
};

/**
 * mempbrk unit test
 */
static void test_mempbrk(void)
{
  size_t i;
  const char *result;
  static const struct {
    const char  *haystack;
    size_t       haylen;
    const char  *needle;
    size_t       needlen;
    const char  *expect;
  } *t, Test[] = {
    /* should fail */
    { "",           0,  "",     0,  NULL   },
    { "",           0,  "A",    1,  NULL   },
    { "A",          1,  "",     0,  NULL   },
    { "A",          1,  "AB",   2,  NULL   },
    { "AB",         2,  "ABC",  3,  NULL   },
    { "AAAAAAAA",   8,  "B",    1,  NULL   },
    { "AB",         1,  "B",    1,  NULL   }, /* ensure we stop where we're told */
    /* should pass*/
    { "A",          1,  "A",    1,  "A"    },
    { "AB",         2,  "B",    1,  "B"    },
    { "ABC",        3,  "AB",   2,  "AB"   },
    { "AAAAAAAB",   8,  "AB",   2,  "AB"   },
    { "AAB",        3,  "AB",   2,  "AB"   },
    { "AABABC",     6,  "ABC",  3,  "ABC"  }
  };
  printf("test_mempbrk\n");
  for (i = 0; i < sizeof Test / sizeof Test[0]; i++) {
    t = Test + i;
    assert('\0' == t->haystack[t->haylen]); /* guard against incorrect test data lengths */
    assert('\0' == t->needle[t->needlen]);
    printf("[%2u] haystack=\"%.*s\" needle=\"%s\" -> \"%s\"... ",
      (unsigned)i, (int)t->haylen, t->haystack, t->needle, t->expect);
    result = mempbrk((char *)t->haystack, (char *)t->needle, t->haylen, t->needlen);
    printf(OkStr[
      (
        (NULL == t->expect && NULL == result) ||
        (NULL != t->expect && NULL != result && 0 == strncmp((char *)result, t->expect, t->needlen)))
    ]);
    printf(" (\"%s\")\n", result);
  }
}


static void test_hexint(void)
{
  assert(0x0 == HexTbl['0']);
  assert(0x1 == HexTbl['1']);
  assert(0x2 == HexTbl['2']);
  assert(0x3 == HexTbl['3']);
  assert(0x4 == HexTbl['4']);
  assert(0x5 == HexTbl['5']);
  assert(0x6 == HexTbl['6']);
  assert(0x7 == HexTbl['7']);
  assert(0x8 == HexTbl['8']);
  assert(0x9 == HexTbl['9']);
  assert(0xA == HexTbl['A'] && 0xA == HexTbl['a']);
  assert(0xB == HexTbl['B'] && 0xB == HexTbl['b']);
  assert(0xC == HexTbl['C'] && 0xC == HexTbl['c']);
  assert(0xD == HexTbl['D'] && 0xD == HexTbl['d']);
  assert(0xE == HexTbl['E'] && 0xE == HexTbl['e']);
  assert(0xF == HexTbl['F'] && 0xF == HexTbl['f']);
  assert(0x0 == hexint('0'));
  assert(0xF == hexint('F'));
  assert(0xF == hexint('f'));
  assert(0   == hexint('\xFF'));
  assert(0   == hexint('Z'));
  assert(0x0000 == hexint4((u8 *)"0000"));
  assert(0xFFFF == hexint4((u8 *)"ffff"));
}

int main(void)
{
  setvbuf(stdout, (char *)NULL, _IONBF, 0); /* unbuffer stdout */
  test_strltrim();
  test_memltrim();
  test_hexint();
  test_base64enc();
  return 0;
}

#endif

