#include <string.h>
#include <ctype.h>

#include "config.h"

/* Functions for cleaning up random strings for logging */
int isjunk(char c)
{
  return ((c < ' ') || (c>126));
}

void dejunkifyforlog(char *s)
{
  int i;
  if (strlen(s)>32)
    s[32]='\0';
  for (i=0; i<strlen(s); i++)
    if (isjunk(s[i]))
      s[i]='.';
}

/* Remove line breaks at end of string */

int choppable(char c)
{
  return (isspace(c));
}

void chop(char *string)
{
  if (string)
    {
      while (strlen(string) && choppable(string[strlen(string)-1]))
	string[strlen(string)-1]='\0';
    }
}

/* Remove all blanks at the beginning and end of a string */

void cleanupstring(char *string)
{
  int i=strlen(string)-1;
  while (i>0 && isspace(string[i]))
    i--;
  string[i+1]='\0';
  i=0;
  while (isspace(string[i]))
    i++;
  memmove(string,&(string[i]),strlen(&(string[i]))+1);
}

