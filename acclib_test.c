#include <stdio.h>

#include "accounting.h"

int accounting_open(char *id)
{
  fprintf(stderr, "accounting_open(%s)\n", id);
  return 1;
}

int accounting_login(char *account, char *session_id)
{
  fprintf(stderr, "accounting_login(%s, %s)\n", account, session_id);
  return 1;
}

int accounting_logout(char *account, char *session_id)
{
  fprintf(stderr, "accounting_logout(%s, %s)\n", account, session_id);
  return 1;
}

int accounting_close()
{
  fprintf(stderr, "accounting_close()\n");
  return 1;
}
