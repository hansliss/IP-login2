/*
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version
 *   2 of the License, or (at your option) any later version.
 *
 *   Hans Liss <hans.liss@its.uu.se>  Uppsala Universitet
 *
 *   The file LICENSE must accompany this package when redistributed.
 *   Please refer to it for specific acknowledgements.
 *
 */


#define malloc(s) mymalloc_malloc(s,__FILE__,__LINE__)
#define calloc(n,s) mymalloc_calloc(n,s,__FILE__,__LINE__)
#define free(p) mymalloc_free(p,__FILE__,__LINE__)
#define realloc(p,s) mymalloc_realloc(p,s,__FILE__,__LINE__)

void *mymalloc_malloc (size_t __size, char *file, int line);
void *mymalloc_calloc (size_t __nmemb, size_t __size, char *file, int line);
void mymalloc_free (void *__ptr, char *file, int line);
void *mymalloc_realloc (void *__ptr, size_t __size, char *file, int line);

void mymalloc_setdebug(int v);
void mymalloc_setperm();
void mymalloc_resetperm();
void mymalloc_pushcontext(char *s);
void mymalloc_popcontext();

