/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 */

#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#ifdef WIN32
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#else
# include <sys/time.h>
#endif
#include "types.h"

#define MIN(a, b)   ((a) < (b) ? a : b)
#define MAX(a, b)   ((a) > (b) ? a : b)

/* little endian to host endianness short */
#define ltohs(x)    x

/* little endian to host endianness short */
#define ltohl(x)    x

/**
 * our own assertion macro that uses LOGF() and doesn't abort() in Release
 */
#ifdef DEBUG
# define ASSERT(x)                                                \
  if (!(x)) {                                                     \
    LOGF(__FILE__, __LINE__, NULL, "ASSERTION FAILED: %s\n", #x); \
  }

#else /* Release, don't abort() on failure */
# define ASSERT(x)                                                \
  if (!(x)) {                                                     \
    LOGF(__FILE__, __LINE__, NULL, "ASSERTION FAILED: %s\n", #x); \
    abort();                                                      \
  }

#endif

void DEBUGF(const char *, unsigned, const char *, ...);
void LOGF(const char *file, unsigned line, const char *fmt, ...);

size_t strlcpy(char *dst, const char *src, size_t size);
size_t strlcat(char *dst, const char *src, size_t size);

size_t dump_bytes(const char *buf, size_t len, FILE *);
size_t dump_bytes_buf(char *dst, size_t dstlen, const char *buf, size_t len);
size_t dump_chars(const char *buf, size_t len, FILE *);
size_t dump_chars_buf(char *dst, size_t dstlen, const char *buf, size_t len);
size_t dump_chars_buf2(char *dst, size_t dstlen, const char *buf, size_t len);
size_t dump_hash_buf(char *dst, size_t dstlen, const u8 *buf, size_t len);

char * strrtrim(char *s);
char * strltrim(char *s);
char * strtrim(char *s);
size_t memltrim(char *, size_t);
size_t memmatch(char *, size_t, int (*)(int));
int str_endswith(const char *str, const char *match);

const char * mempbrk(const char *hay, const char *need, size_t haylen, size_t needlen);
const char * memstr(const char *hay, const char *needle, size_t haylen);
const char * memrstr(const char *hay, const char *need, size_t haylen);

size_t memspn(const char *mem, size_t memlen, const char *accept, size_t acceptlen);
size_t memcspn(const char *mem, size_t memlen, const char *reject, size_t rejectlen);

char hexint (const u8);
char hexint2(const u8 *);
unsigned      hexint3(const u8 *);
unsigned      hexint4(const u8 *);
unsigned long hexint8(const u8 *);

#define BASE64_ENCBUF(inbytes)   (((inbytes) * 2) + 3) /* calculate the bytes necessary to hold base64 output */
                                                       /* NOTE: this is quick and easy but is actually larger than it needs to be */
size_t base64enc(const char *src, size_t srclen, char *dst, size_t dstlen);

void strupper(char *s, size_t len);
void strlower(char *s, size_t len);

size_t decode_hex_dump(char *dst, size_t dstlen, const char *src, size_t srclen);

int allzeroes(const char *c, size_t len);
int allones  (const char *c, size_t len);

#endif

