#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>

#include "config.h"
#include "divlib.h"

/* Translate an ASCII hostname or ip address to a struct in_addr - return 0
   if unable */
int makeaddress(char *name_or_ip, struct in_addr *res)
{
  struct hostent *listen_he;
  if (!inet_aton(name_or_ip,res))
    {
      if (!(listen_he=gethostbyname(name_or_ip)))
	return 0;
      else
	{
	  memcpy(res, listen_he->h_addr_list[0], sizeof(res));
	  return 1;
	}
    }
  else
    return 1;
}

/* Translate a service name or port number (as a string) into an NBO
   integer. Return 0 on failure. */

int makeport(char *name_or_port)
{
  struct servent *listen_se;
  int listen_port;
  char *c;
  listen_port=strtol(name_or_port,&c,10);
  if (c != '\0')
    {
      if (!(listen_se=getservbyname(name_or_port, "tcp")))
	{
	  if (sscanf(name_or_port,"%i",&listen_port)<1)
	    {
	      listen_port=0;
	    }
	  else
	    listen_port=htons(listen_port);
	}
      else
	listen_port=listen_se->s_port;
    }
  else
    listen_port=htons(listen_port);
  return listen_port;
}

