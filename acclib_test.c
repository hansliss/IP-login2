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
