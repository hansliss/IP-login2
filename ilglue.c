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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "makeaddress.h"
#include "conffile.h"
#include "hlcrypt.h"
#include <iplogin2.h>

#define BUFSIZE 8192
#define DEFAULT_SYSLOG_FACILITY LOG_LOCAL5
#define READ_TIMEOUT 10000

void initialize_log(char *progname_in, int syslog_facility)
{
  static char progname[BUFSIZE];
  strncpy(progname, progname_in, BUFSIZE);
  progname[BUFSIZE-1]='\0';
  openlog(progname,LOG_PID,syslog_facility);
}

int initialize(char *clientname, char *conffile,
	       struct sockaddr_in *server_address, char *servername, int snamelen)
{
  struct servent *server_se;
  int i;
  char tmpbuf[BUFSIZE], *c;
  int server_port;
  struct in_addr my_inaddr;
  int syslog_facility;

  syslog_facility=DEFAULT_SYSLOG_FACILITY;

  /* Open the configuration file or fail. This is a test */
  if (!conf_init(conffile))
    {
      fprintf(stderr,"Error opening configuration file %s\n",conffile);
      return 0;
    }

  conf_cleanup();

  /* Find out what facility to syslog to. Default is defined at top */
  if (conf_getvar(conffile,"client",clientname,"syslog_facility",
		  tmpbuf,BUFSIZE))
    {
      for (i=0;facilitynames[i].c_name;i++)
	if (!strcasecmp(tmpbuf,facilitynames[i].c_name))
	  syslog_facility=facilitynames[i].c_val;
    }

  /* Find out our program name for syslog */
  if (!conf_getvar(conffile,"client",clientname,"syslog_name",tmpbuf,BUFSIZE))
    {
      fprintf(stderr,"syslog_name is missing for this client.\n");
      return 0;
    }

  /* Open the syslog */
  initialize_log(tmpbuf, syslog_facility);

  if (!conf_getvar(conffile,"client",clientname,
		   "servername", tmpbuf, BUFSIZE))
    {
      syslog(LOG_ERR,"servername is missing for this client.");
      return 0;
    }
  strncpy(servername, tmpbuf, snamelen);

  /* Find out what address to connect to. An address must be given in the
     configuration file and it must be an IP address in dot notation or a
     resolvable host name */
  server_address->sin_family=AF_INET;
  if (!conf_getvar(conffile,"server",servername,"ip",tmpbuf,BUFSIZE))
    {
      syslog(LOG_ERR,
	     "ip is missing for the server \"%s\". Check configuration file",
	     servername);
      return 0;
    }
  else
    {
      if (!makeaddress(tmpbuf,&my_inaddr))
	{
	  syslog(LOG_ERR,"Unknown server address %s",tmpbuf);
	  closelog();
	  return 0;
	}
      else
	server_address->sin_addr.s_addr=my_inaddr.s_addr;
    }

  /* Find out what port to connect to. Numerical port number or
     service name is OK */
  if (!conf_getvar(conffile,"client",clientname,"server_port",tmpbuf,BUFSIZE))
    {
      syslog(LOG_ERR, "server_port is unknown for this client");
      closelog();
      return 0;
    }
  else
    {
      server_port=strtol(tmpbuf,&c,10);
      if (c != '\0')
	{
	  if (!(server_se=getservbyname(tmpbuf, "tcp")))
	    {
	      if (sscanf(tmpbuf,"%i",&server_port)<1)
		{
		  syslog(LOG_ERR, "server_port %s is bad for %s",
			 tmpbuf,clientname);
		  closelog();
		  return 0;
		}
	      else
		server_port=htons(server_port);
	    }
	  else
	    server_port=server_se->s_port;
	}
      else
	server_port=htons(server_port);
    }
  server_address->sin_port=server_port;

  return 1;
}

int do_connect(char *conffile, char *clientname, int *csocket,HLCRYPT_HANDLE *h)
{
  struct sockaddr_in my_server_address;
  char servername[1024];
  char local_key[BUFSIZE], remote_key[BUFSIZE];

  if (!initialize(clientname, conffile, &my_server_address, servername, sizeof(servername)))
    {
      fprintf(stderr,"Giving up.\n");
      return 0;
    }

#if 0
  fprintf(stderr,"%s: Connecting to %s:%d\n", clientname,
	  inet_ntoa(my_server_address.sin_addr),
	  ntohs(my_server_address.sin_port));
#endif

  if (((*csocket)=socket(AF_INET,SOCK_STREAM,0))==-1)
    {
      syslog(LOG_ERR,"socket(): %m");
      return 0;
    }
  if (connect(*csocket, (struct sockaddr *)&my_server_address,
	      sizeof(my_server_address))!=0)
    {
      syslog(LOG_ERR,"connect(): %m");
      return 0;
    }

  if (!conf_getvar(conffile,"server",servername,"key",
		   remote_key,sizeof(remote_key)))
    {
      syslog(LOG_ERR,"No server key is defined for %s",servername);
      return 0;
    }

  if (!conf_getvar(conffile,"client",clientname,"key",
		   local_key,sizeof(local_key)))
    {
      syslog(LOG_ERR,"No client key is defined for %s", clientname);
      return 0;
    }

  if (hlcrypt_AuthClient(*csocket, local_key, remote_key, h))
    return 1;
  else
    return 0;
}

int iplogin2_login(char *conffile, char *clientname,
	  char *address, char *account, char *chains)
{
  unsigned char tmpbuf[BUFSIZE];
  int n,i;
  int csocket;
  HLCRYPT_HANDLE h=NULL;
  if (!do_connect(conffile, clientname, &csocket, &h))
    return 0;
  sprintf(tmpbuf,"add %.128s %.128s %.128s", address, account, chains);
  hlcrypt_Send(csocket,tmpbuf, h);
  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h) > 0)
    {
      sscanf(tmpbuf,"%i",&n);
      for (i=0; i<n; i++)
	{
	  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h) <= 0)
	    break;
	}
    }
  close(csocket);
  if (!strcmp(tmpbuf,"OK"))
    return 1;
  else
    return 0;
}

int iplogin2_logout(char *conffile, char *clientname,
	   char *address)
{
  unsigned char tmpbuf[BUFSIZE];
  int n,i;
  int csocket;
  HLCRYPT_HANDLE h=NULL;
  if (!do_connect(conffile, clientname, &csocket, &h))
    return 0;
  sprintf(tmpbuf,"del %.128s", address);
  hlcrypt_Send(csocket,tmpbuf, h);
  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h) > 0)
    {
      sscanf(tmpbuf,"%i",&n);
      for (i=0; i<n; i++)
	{
	  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h) <= 0)
	    break;
	}
    }
  close(csocket);
  if (!strcmp(tmpbuf,"OK"))
    return 1;
  else
    return 0;
}

int iplogin2_check(char *conffile, char *clientname, char *address)
{
  unsigned char tmpbuf[BUFSIZE];
  int n,r;
  int csocket;
  HLCRYPT_HANDLE h=NULL;
  if (!do_connect(conffile, clientname, &csocket, &h))
    return 0;
  r=0;
  sprintf(tmpbuf,"check %.128s", address);
  hlcrypt_Send(csocket,tmpbuf,h);
  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h) > 0)
    {
      sscanf(tmpbuf,"%i",&n); /* Should be 1 */
      if ((n == 1) &&
	  (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h) >0) &&
	  !strcasecmp(tmpbuf, "Yes"))
	r=1;
    }
  close(csocket);
  return r;
}

int iplogin2_stat(char *conffile, char *clientname, char *address, namelist *lines)
{
  unsigned char tmpbuf[BUFSIZE];
  int n,i,r;
  int csocket;
  HLCRYPT_HANDLE h=NULL;
  if (!do_connect(conffile, clientname, &csocket, &h))
    return 0;
  r=1;
  sprintf(tmpbuf,"stat %.128s", address);
  hlcrypt_Send(csocket,tmpbuf,h);
  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h) > 0)
    {
      sscanf(tmpbuf,"%i",&n);
      for (i=0; i<n; i++)
	{
	  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h) <= 0)
	    break;
	  else
	    addname(lines,tmpbuf);
	}
    }
  else
    r=0;
  if (lines &&
      !strncmp((*lines)->name, "ERROR", 5))
    r=0;
  close(csocket);
  return r;
}

int iplogin2_docommand(char *conffile, char *clientname,
	       char *command, namelist *lines)
{
  unsigned char tmpbuf[BUFSIZE];
  int n,i;
  int csocket;
  HLCRYPT_HANDLE h=NULL;
  if (!do_connect(conffile, clientname, &csocket, &h))
    return 0;
  hlcrypt_Send(csocket,command,h);
  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT,h) > 0)
    {
      sscanf(tmpbuf,"%i",&n);
      for (i=0; i<n; i++)
	{
	  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT,h) <= 0)
	    break;
	  else
	    addname(lines,tmpbuf);
	}
    }
  close(csocket);
  return 1;
}

