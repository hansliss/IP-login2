#include "autoconfig.h"
#if HAVE_LIBDL == 1
#include <dlfcn.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *last_error=NULL;
int last_error_set=0;

typedef int accounting_open(char *);
typedef int accounting_login(char *, char *);
typedef int accounting_logout(char *, char *);
typedef int accounting_close();

void *acct_init(char *libname, char *progname)
{
#if HAVE_LIBDL == 1
  accounting_open *lfunc;
  void *handle=dlopen(libname,RTLD_NOW);
  if (handle)
    {
      lfunc=(accounting_open *)dlsym(handle, "accounting_open");
      if (lfunc!=NULL)
	lfunc(progname);
    }
  return handle;
#else
  return NULL;
#endif
}

int acct_cleanup(void *handle)
{
#if HAVE_LIBDL == 1
  accounting_close *lfunc;
  lfunc=(accounting_close *)dlsym(handle, "accounting_close");
  if (lfunc!=NULL)
    lfunc();
  return dlclose(handle);
#else
  return 0;
#endif
}

int acct_login(void *handle, char *account, char *session_id)
{
#if HAVE_LIBDL == 1
  accounting_login *lfunc=(accounting_login *)dlsym(handle, "accounting_login");
  if (lfunc!=NULL)
    return lfunc(account, session_id);
  else
#endif
    return 0;
}

int acct_logout(void *handle, char *account, char *session_id)
{
#if HAVE_LIBDL == 1
  accounting_logout *lfunc=(accounting_logout *)dlsym(handle, "accounting_logout");
  if (lfunc!=NULL)
    return lfunc(account, session_id);
  else
#endif
    return 0;
}

char *acct_last_error()
{
#if HAVE_LIBDL == 1
  if (!last_error_set)
    return dlerror();
  else
    {
      last_error_set=0;
      return last_error;
    }
#else
  return "Accounting disabled by configure";
#endif
}

