#include <dlfcn.h>
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
  accounting_open *lfunc;
  void *handle=dlopen(libname,RTLD_NOW);
  if (handle)
    {
      lfunc=(accounting_open *)dlsym(handle, "accounting_open");
      if (lfunc!=NULL)
	lfunc(progname);
    }
  return handle;
}

int acct_cleanup(void *handle)
{
  accounting_close *lfunc;
  lfunc=(accounting_close *)dlsym(handle, "accounting_close");
  if (lfunc!=NULL)
    lfunc();
  return dlclose(handle);
}

int acct_login(void *handle, char *account, char *session_id)
{
  accounting_login *lfunc=(accounting_login *)dlsym(handle, "accounting_login");
  if (lfunc!=NULL)
    return lfunc(account, session_id);
  else
    return 0;
}

int acct_logout(void *handle, char *account, char *session_id)
{
  accounting_logout *lfunc=(accounting_logout *)dlsym(handle, "accounting_logout");
  if (lfunc!=NULL)
    return lfunc(account, session_id);
  else
    return 0;
}

char *acct_last_error()
{
  if (!last_error_set)
    return dlerror();
  else
    {
      last_error_set=0;
      return last_error;
    }
}

