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

void recalc(struct config *conf, int number_of_users)
{
  int margin;
  int lt=conf->logout_timeout - conf->missdiff;
  int pi=conf->pinginterval;
  int mm=conf->maxmissed;
  if (lt<=0)
    lt=1; /* Wrong but safe */
  conf->maxmissed=DEFAULT_MISSED;

  if ((number_of_users * conf->maxmissed) == 0)
    conf->pinginterval=conf->min_pinginterval;
  else
    conf->pinginterval=(1000000 * lt)/(number_of_users * conf->maxmissed);
  if (conf->pinginterval<conf->min_pinginterval)
    {
      conf->pinginterval=conf->min_pinginterval;
      if ((number_of_users * conf->pinginterval) == 0)
	conf->maxmissed=MIN_MISSED;
      else
	conf->maxmissed=(1000000 * lt)/(number_of_users * conf->pinginterval);
      if (conf->maxmissed<MIN_MISSED)
	{
	  conf->maxmissed=MIN_MISSED;
	  conf->logout_timeout=number_of_users * conf->maxmissed * conf->pinginterval / 1000000 + conf->missdiff;
	}
    }
  if ((pi != conf->pinginterval) ||
      (mm != conf->maxmissed))
    syslog(LOG_DEBUG, "Users: %d - New ping interval: %d us, new maxmissed=%d\n",
	    number_of_users, conf->pinginterval, conf->maxmissed);
  margin=1000000 * conf->logout_timeout / conf->maxmissed -
    number_of_users * conf->min_pinginterval;
}
