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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "config.h"

int getRSS()
{
  int memsize;
  FILE *statfile;
  static char buf[4096];
  static char sfilename[1024];
  static int pid=0;
  if (!pid)
    {
      pid=getpid();
      sprintf(sfilename, "/proc/%d/status", pid);
    }

  statfile=fopen(sfilename,"r");

  fseek(statfile,0,SEEK_SET);
  while (fgets(buf,sizeof(buf),statfile) &&
	 strncmp(buf,"VmRSS",5));
  sscanf(buf,"VmRSS:  %i kB",&memsize);
  fclose(statfile);
  return memsize;
}

unsigned long getvsize()
{
  unsigned long vsize;
  FILE *statfile;
  static char buf[8192];
  static char sfilename[1024];
  static int pid=0;
  if (!pid)
    {
      pid=getpid();
      sprintf(sfilename, "/proc/%d/stat", pid);
    }

  statfile=fopen(sfilename,"r");

  fgets(buf,sizeof(buf),statfile);
  sscanf(buf,"%*s %*s %*c %*s %*s %*s %*s %*s %*s %*s \
%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %*s %*s %*s %*s %*s %*s \
%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s",&vsize);

  fclose(statfile);
  return vsize;
}

#define DEFAULT_MISSED 5
#define MIN_MISSED 2

void recalc(struct pingconfig *pingconf, int logout_timeout, int number_of_users)
{
  /*  int margin;*/
  int lt=logout_timeout - pingconf->missdiff;
  int pi=pingconf->pinginterval;
  int mm=pingconf->maxmissed;
  if (lt<=0)
    lt=1; /* Wrong but safe */
  pingconf->maxmissed=DEFAULT_MISSED;

  if ((number_of_users * pingconf->maxmissed) == 0)
    pingconf->pinginterval=pingconf->min_pinginterval;
  else
    pingconf->pinginterval=(1000000 * lt)/(number_of_users * pingconf->maxmissed);
  if (pingconf->pinginterval<pingconf->min_pinginterval)
    {
      pingconf->pinginterval=pingconf->min_pinginterval;
      if ((number_of_users * pingconf->pinginterval) == 0)
	pingconf->maxmissed=MIN_MISSED;
      else
	pingconf->maxmissed=(1000000 * lt)/(number_of_users * pingconf->pinginterval);
      if (pingconf->maxmissed<MIN_MISSED)
	{
	  pingconf->maxmissed=MIN_MISSED;
	  logout_timeout=number_of_users * 
	    pingconf->maxmissed *
	    pingconf->pinginterval / 1000000
	    + pingconf->missdiff;
	}
    }
  if ((pi != pingconf->pinginterval) ||
      (mm != pingconf->maxmissed))
    syslog(LOG_DEBUG, "Users: %d - New ping interval: %d us, new maxmissed=%d\n",
	    number_of_users, pingconf->pinginterval, pingconf->maxmissed);
  /*  margin=1000000 * logout_timeout / pingconf->maxmissed -
    number_of_users * pingconf->min_pinginterval;*/
}

int
check_inverse(const char option[], int *invert)
{
        return 0;
}

u_int16_t parse_protocol(const char *s)
{
  return 0;
}
void parse_hostnetworkmask(const char *name, struct in_addr **addrpp, struct in_addr *maskp, unsigned int *naddrs)
{
}
char *addr_to_anyname(const struct in_addr *addr)
{
  return NULL;
}
char *mask_to_dotted(const struct in_addr *mask)
{
  return NULL;
}

