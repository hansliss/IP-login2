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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iplogin2.h>
#include <sys/types.h>
#include <sys/stat.h>

#define CFILE1 "/opt/iplogin2/etc/iplogin2.conf"
#define CFILE2 "/usr/local/etc/iplogin.conf"

#define BUFSIZE 8192

int main(int argc, char *argv[])
{
  namelist lines=NULL;
  int count=0;
  int retry=3;
  struct stat statbuf;
  char *conffile;
  char *clientname;
  if (argc!=3)
    {
      fprintf(stderr,"Usage: %s <conffile> <clientname>\n",argv[0]);
      return 1;
    }
  
  conffile = argv[1];
  clientname = argv[2];

  if (!strcasecmp(conffile, "."))
    {
      if (!stat(CFILE1, &statbuf))
	conffile=CFILE1;
      else
	if (!stat(CFILE2, &statbuf))
	  conffile=CFILE2;
    }
  if (!strcasecmp(clientname, "."))
    clientname="localhost";

  while (retry-- &&
	 !iplogin2_docommand(conffile, clientname, "count", &lines))
    {
      sleep(2);
    }
  if (!retry)
    {
      printf("-1\n");
      return -1;
    }
  if (!lines)
    {
      printf("-1\n");
      return -1;
    }
  count=atoi(lines->name);
  freenamelist(&lines);
  printf("%d\n", count);
  return 0;
}
