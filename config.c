#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "config.h"

char *params(struct config *conf)
{
  static char pbuf[CONFBSIZE];
  sprintf(pbuf,"%s/%s: [%d %d %d %d %d %d %d]%s%s%s",
	  conf->conffile,
	  conf->servername,
	  conf->accept_interval,
	  conf->accept_timeout,
	  conf->logout_timeout,
	  conf->defaultping.pinginterval,
	  conf->defaultping.min_pinginterval,
	  conf->defaultping.missdiff,
	  conf->defaultping.maxmissed,
	  strlen(conf->loadfile)?" (loaded state from ":"",
	  conf->loadfile,
	  strlen(conf->loadfile)?")":""
	  );
  return pbuf;
}
