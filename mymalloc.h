
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

