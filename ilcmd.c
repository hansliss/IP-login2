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
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "autoconfig.h"
#include "conffile.h"
#include "hlcrypt.h"
#include <iplogin2.h>

#define BUFSIZE 8192
#define DEFAULT_SYSLOG_FACILITY LOG_LOCAL5
#define READ_TIMEOUT 10000

#define CFILE1 "/opt/iplogin2/etc/iplogin2.conf"
#define CFILE2 "/usr/local/etc/iplogin.conf"

void initialize_log(char *progname_in, int syslog_facility)
{
  static char progname[BUFSIZE];
  strncpy(progname, progname_in, BUFSIZE);
  progname[BUFSIZE-1]='\0';
  openlog(progname,LOG_PID,syslog_facility);
}

int initialize(char *clientname, char *conffile, struct sockaddr_in *server_address, char *servername)
{
  struct hostent *server_he;
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
  if (conf_getvar(conffile,"client",clientname,"syslog_facility",tmpbuf,BUFSIZE))
    {
      for (i=0;facilitynames[i].c_name;i++)
	if (!strcasecmp(tmpbuf,facilitynames[i].c_name))
	  syslog_facility=facilitynames[i].c_val;
    }

  /* Find out our program name for syslog */
  if (!conf_getvar(conffile,"client",clientname,"syslog_name",tmpbuf,BUFSIZE))
    {
      fprintf(stderr,"syslog_name is missing for this <client>. Check configuration file\n");
      return 0;
    }

  /* Open the syslog */
  initialize_log(tmpbuf, syslog_facility);

  if (!conf_getvar(conffile,"client",clientname, "servername", tmpbuf, BUFSIZE))
    {
      syslog(LOG_ERR,"servername is missing for this <client>. Check configuration file");
      return 0;
    }
  strcpy(servername, tmpbuf);

  /* Find out what address to connect to. An address must be given in the configuration
     file and it must be an IP address in dot notation or a resolvable host name */
  server_address->sin_family=AF_INET;
  if (!conf_getvar(conffile,"server",servername,"ip",tmpbuf,BUFSIZE))
    {
      syslog(LOG_ERR,"ip is missing for the server \"%s\". Check configuration file",servername);
      return 0;
    }
  else
    {
      if (!inet_aton(tmpbuf,&my_inaddr))
	{
	  if (!(server_he=gethostbyname(tmpbuf)))
	    {
	      syslog(LOG_ERR,"Unknown server address %s",tmpbuf);
	      closelog();
	      return 0;
	    }
	  else
	    {
	      server_address->sin_family=server_he->h_addrtype;
	      memcpy(&(server_address->sin_addr), server_he->h_addr_list[0], sizeof(server_address->sin_addr));
	    }
	}
      else
	server_address->sin_addr.s_addr=my_inaddr.s_addr;
    }

  /* Find out what port to connect to. Numerical port number or service name is OK */
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
		  syslog(LOG_ERR, "server_port %s is bad for %s",tmpbuf,clientname);
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

void do_command(int csocket, char *command)
{
  unsigned char tmpbuf[BUFSIZE];
  int n,i;
  hlcrypt_Send(csocket,command, NULL);
  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, NULL) > 0)
    {
      sscanf(tmpbuf,"%i",&n);
      for (i=0; i<n; i++)
	{
	  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, NULL) > 0)
	    printf("- %s\n",tmpbuf);
	  else
	    printf("[error]\n");
	}
    }
}

int main(int argc, char *argv[])
{
  int mysocket;
  struct sockaddr_in my_server_address;
  char *conffile, *clientname;
  struct stat statbuf;
  char servername[1024];
  struct in_addr my_inaddr;
  char local_key[BUFSIZE], remote_key[BUFSIZE];

  if (argc!=4)
    {
      fprintf(stderr,"Usage: %s <configuration file> <client name> <command>\n",argv[0]);
      return 1;
    }
  conffile=argv[1];
  clientname=argv[2];

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

  if (!initialize(clientname, conffile, &my_server_address, servername))
    {
      fprintf(stderr,"Giving up.\n");
      return 1;
    }
  my_inaddr.s_addr=my_server_address.sin_addr.s_addr;
  fprintf(stderr,"%s: Connecting to %s:%d\n", clientname, inet_ntoa(my_inaddr), ntohs(my_server_address.sin_port));
  if ((mysocket=socket(AF_INET,SOCK_STREAM,0))==-1)
    {
      syslog(LOG_ERR,"socket(): %m");
      return 2;
    }
  if (connect(mysocket, (struct sockaddr *)&my_server_address, sizeof(my_server_address))!=0)
    {
      syslog(LOG_ERR,"connect(): %m");
      return 1;
    }

  if (!conf_getvar(conffile,"server",servername,"key",remote_key,sizeof(remote_key)))
    {
      syslog(LOG_ERR,"No server key is defined for %s in configuration file",servername);
      return 2;
    }

  if (!conf_getvar(conffile,"client",clientname,"key",local_key,sizeof(local_key)))
    {
      syslog(LOG_ERR,"No client key is defined for %s in configuration file",clientname);
      return 2;
    }

  if (hlcrypt_AuthClient(mysocket, local_key, remote_key, NULL))
    do_command(mysocket, argv[3]);

  closelog();
  close(mysocket);
  return 0;
}
