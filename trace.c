#include <stdio.h>
#include <sys/timeb.h>
#include <time.h>
#include <hl.h>

FILE *tracefile=NULL;

void trace_init(char *conffile, char *servername)
{
  char tmpbuf[8192];
  if (conf_getvar(conffile, "server", servername, "tracefile", tmpbuf, sizeof(tmpbuf)))
    tracefile=fopen(tmpbuf,"a");
}

void trace_msg(char *msg)
{
  struct timeb now;
  struct tm *now_tm;
  if (tracefile)
    {
      ftime(&now);
      now_tm=localtime(&(now.time));
      fprintf(tracefile, "%04d-%02d-%02d %02d.%02d.%02d.%03d\t%s\n",
	      now_tm->tm_year+1900,
	      now_tm->tm_mon+1,
	      now_tm->tm_mday,
	      now_tm->tm_hour,
	      now_tm->tm_min,
	      now_tm->tm_sec,
	      now.millitm,
	      msg);
      fflush(tracefile);
    }
}

void trace_quit()
{
  if (tracefile)
    fclose(tracefile);
}
