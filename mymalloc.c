#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>

struct _context
{
  char *s;
  struct _context *next;
} *cstack=NULL;

int perm=0;
int malloc_debug=0;

struct _allocinfo
{
  void *ptr;
  size_t size;
  size_t nmemb;
  int perm;
  char *context;
  char *file;
  int line;
  struct _allocinfo *next;
} *ainfo=NULL;

void addnode(struct _allocinfo **node, void *ptr, size_t size, size_t nmemb,
	     char *file, int line)
{
  struct _allocinfo *newnode=malloc(sizeof(struct _allocinfo));
  newnode->ptr=ptr;
  newnode->size=size;
  newnode->nmemb=nmemb;
  newnode->perm=perm;
  newnode->file=file;
  newnode->line=line;
  if (cstack)
    newnode->context=cstack->s;
  else
    newnode->context=NULL;
  newnode->next=(*node);
  (*node)=newnode;
}

void delnode(struct _allocinfo **node, void *ptr)
{
  struct _allocinfo *tmpnode;
  if (!(*node))
    return;
  if ((*node)->ptr == ptr)
    {
      tmpnode=(*node);
      (*node)=(*node)->next;
      free(tmpnode);
    }
  else
    delnode(&((*node)->next), ptr);
}

void *mymalloc_malloc(size_t __size, char *file, int line)
{
  void *__ptr;
  if (malloc_debug && perm)
    syslog(LOG_DEBUG,"%s: malloc(%d)",cstack?cstack->s:"<no context>",__size);
  __ptr=malloc(__size);
  memset(__ptr,0,__size);
  if (malloc_debug)
    addnode(&ainfo,__ptr,__size,1,file,line);
  return __ptr;
}

void *mymalloc_calloc(size_t __nmemb, size_t __size, char *file, int line)
{
  void *__ptr;
  if (malloc_debug && perm)
    syslog(LOG_DEBUG,"%s: calloc(%d, %d)",cstack?cstack->s:"<no context>",__nmemb,__size);
  if (__nmemb*__size==4096)
    syslog(LOG_DEBUG,"%s: calloc(%d, %d)",cstack?cstack->s:"<no context>",__nmemb,__size);
  __ptr=calloc(__nmemb, __size);
  if (malloc_debug)
    addnode(&ainfo,__ptr,__size,__nmemb,file,line);
  return __ptr;
}

void mymalloc_free(void *__ptr, char *file, int line)
{
  if (malloc_debug)
    delnode(&ainfo, __ptr);
  free(__ptr);
}

void *mymalloc_realloc(void *__ptr, size_t __size, char *file, int line)
{
  if (malloc_debug && perm)
    syslog(LOG_DEBUG,"%s: realloc(?, %d)",cstack?cstack->s:"<no context>",__size);
  if (malloc_debug)
    delnode(&ainfo, __ptr);
  __ptr=realloc(__ptr, __size);
  if (malloc_debug)
    addnode(&ainfo, __ptr, __size, 1,file,line);
  return __ptr;
}

void mymalloc_pushcontext(char *s)
{
  struct _context *newc;
  if (malloc_debug)
    {
      newc=malloc(sizeof(struct _context));
      newc->s=s;
      newc->next=cstack;
      cstack=newc;
    }
}

void mymalloc_popcontext()
{
  struct _context *c=cstack;
  struct _allocinfo *anode;
  if (malloc_debug)
    {
      if (c)
	{
	  for (anode=ainfo; anode; anode=anode->next)
	    if (!(anode->perm) && (anode->context==c->s))
	      {	 
		syslog(LOG_NOTICE,
		       "Leaving %s: forgotten pointer 0x%08X to %dx%d bytes memory block allocated in %s line %d\n",
		       c->s, (unsigned int)(anode->ptr), anode->nmemb, anode->size, anode->file, anode->line);
		fflush(stdout);
	      }
	  cstack=cstack->next;
	  free(c);
	}
    }
}

void mymalloc_setdebug(int v)
{
  malloc_debug=v;
  syslog(LOG_NOTICE,"malloc() debugging is %s",v?"on":"off");
}

void mymalloc_setperm()
{
  perm=1;
}

void mymalloc_resetperm()
{
  perm=0;
}
