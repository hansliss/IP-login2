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
