#ifndef	_STRING_H
#define	_STRING_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

typedef unsigned long size_t;
typedef unsigned long uintptr_t;

void *memchr (const void *, int, size_t);

char *strcpy (char *__restrict, const char *__restrict);

char *strrchr (const char *, int);

char *strtok (char *__restrict, const char *__restrict);

char *strtok_r (char *__restrict, const char *__restrict, char **__restrict);

#ifdef __cplusplus
}
#endif

#endif
