#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SYSLOG_NAMES
#define SYSLOG_NAMES_H
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netdb.h>

#include <hl.h>
#include "usernode.h"
#include "engine.h"
#include "config.h"
#include "trace.h"
#include "accounting.h"

char *versionstring_parts[]=
{
  PACKAGE,
  VERSION,
  __DATE__,
  __TIME__
};

#define VERSIONSTRING_PCOUNT (sizeof(versionstring_parts)/sizeof(char *))

int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;

unsigned int alarmtime;

#define RET_GENERAL 1
#define RET_INVOKE 2
#define RET_SOCKET 3
#define RET_INIT 4

#define BUFSIZE 8192
#define DEFAULT_SYSLOG_FACILITY LOG_LOCAL5

char *versionstring(char *buf, int bufsize)
{
  static char vstring[BUFSIZE];
  static int statbuf_done=0;
  int i;
  if (!statbuf_done)
    {
      vstring[0]='\0';
      for (i=0; i<VERSIONSTRING_PCOUNT; i++)
	{
	  if ((strlen(vstring) + strlen(versionstring_parts[i]) + 2) < BUFSIZE)
	    {
	      strcat(vstring, versionstring_parts[i]);
	      if (i < (VERSIONSTRING_PCOUNT-1))
		strcat(vstring," ");
	    }
	}
      statbuf_done=1;
    }
  if (buf)
    {
      strncpy(buf,vstring,bufsize);
      buf[bufsize-1]='\0';
      return buf;
    }
  else
    return vstring;
}

void initialize_log(char *progname_in, int syslog_facility)
{
  static char progname[BUFSIZE];
  strncpy(progname, progname_in, BUFSIZE);
  progname[BUFSIZE-1]='\0';
  openlog(progname, LOG_PID, syslog_facility);
}

int initialize(struct config *conf)
{
  struct hostent *listen_he;
  struct servent *listen_se;
  int i;
  char tmpbuf[BUFSIZE], tmpbuf2[BUFSIZE], *c;
  int listen_port;
  struct in_addr my_inaddr;
  FILE *tmpfile;
  int syslog_facility;
  namelist tmpidlehost=NULL, tmphosts=NULL, tmphosts2=NULL;
  struct network *idlehost;
  unsigned int netmask_cidr, splitnum;

  syslog_facility=DEFAULT_SYSLOG_FACILITY;

  /* Open the configuration file or fail. This is a test */
  if (!conf_init(conf->conffile))
    {
      fprintf(stderr,"Error opening configuration file %s\n",conf->conffile);
      return 0;
    }
  conf_cleanup();

  /* Find out what facility to syslog to. Default is defined at top */
  if (conf_getvar(conf->conffile,"server",conf->servername,"syslog_facility",tmpbuf,BUFSIZE))
    {
      for (i=0;facilitynames[i].c_name;i++)
	if (!strcasecmp(tmpbuf,facilitynames[i].c_name))
	  syslog_facility=facilitynames[i].c_val;
    }

  /* Find out our program name for syslog */
  if (!conf_getvar(conf->conffile,"server",conf->servername,"syslog_name",tmpbuf,BUFSIZE))
    {
      fprintf(stderr,"syslog_name is missing for this <server>. Check configuration file\n");
      return 0;
    }

  strncpy(conf->progname,tmpbuf,CONFBSIZE);
  conf->progname[CONFBSIZE-1]='\0';
  /* Open the syslog */
  initialize_log(conf->progname, syslog_facility);

  if (conf_getvar(conf->conffile,"server",conf->servername,"pidfile",conf->pidfile,CONFBSIZE))
    {
      if (!(tmpfile=fopen(conf->pidfile,"w")))
	{
	  perror(conf->pidfile);
	  syslog(LOG_ERR,"%s: %m",conf->pidfile);
	  return 0;
	}
      else
	{
	  fprintf(tmpfile,"%d\n",getpid());
	  fclose(tmpfile);
	}
    }
  else
    conf->pidfile[0]='\0';

  /* Find out what address to listen to. If an address is given in the configuration
     file, it must be "any", a IP address in dot notation or a resolvable host name */
  conf->listen_address.sin_family=AF_INET;
  if ((!conf_getvar(conf->conffile,"server",conf->servername,"listen_address",tmpbuf,BUFSIZE)) ||
      !strcasecmp(tmpbuf,"any"))
    conf->listen_address.sin_addr.s_addr=INADDR_ANY;
  else
    {
      if (!inet_aton(tmpbuf,&my_inaddr))
	{
	  if (!(listen_he=gethostbyname(tmpbuf)))
	    {
	      syslog(LOG_ERR,"Unknown listen address %s",tmpbuf);
	      closelog();
	      return 0;
	    }
	  else
	    {
	      conf->listen_address.sin_family=listen_he->h_addrtype;
	      memcpy(&(conf->listen_address.sin_addr), listen_he->h_addr_list[0],
		     sizeof(conf->listen_address.sin_addr));
	    }
	}
      else
	conf->listen_address.sin_addr.s_addr=my_inaddr.s_addr;
    }

  /* Find out what port to listen to. Numerical port number or service name is OK */
  if (!conf_getvar(conf->conffile,"server",conf->servername,"listen_port",tmpbuf,BUFSIZE))
    {
      syslog(LOG_ERR, "listen_port is unknown for %s",conf->servername);
      closelog();
      return 0;
    }
  else
    {
      listen_port=strtol(tmpbuf,&c,10);
      if (c != '\0')
	{
	  if (!(listen_se=getservbyname(tmpbuf, "tcp")))
	    {
	      if (sscanf(tmpbuf,"%i",&listen_port)<1)
		{
		  syslog(LOG_ERR, "listen_port %s is bad for %s",tmpbuf,conf->servername);
		  closelog();
		  return 0;
		}
	      else
		listen_port=htons(listen_port);
	    }
	  else
	    listen_port=listen_se->s_port;
	}
      else
	listen_port=htons(listen_port);
    }
  conf->listen_address.sin_port=listen_port;

  if (conf_getvar(conf->conffile, "server", conf->servername, "accept_interval", tmpbuf, BUFSIZE)!=0)
    {
      sscanf(tmpbuf,"%i",&(conf->accept_interval));
    }
  else
    conf->accept_interval=20;
  if (conf_getvar(conf->conffile, "server", conf->servername, "accept_timeout", tmpbuf, BUFSIZE)!=0)
    {
      sscanf(tmpbuf,"%i",&(conf->accept_timeout));
    }
  else
    conf->accept_timeout=200;
  if (conf_getvar(conf->conffile, "server", conf->servername, "logout_timeout", tmpbuf, BUFSIZE)!=0)
    {
      sscanf(tmpbuf,"%i",&(conf->logout_timeout));
    }
  else
    conf->logout_timeout=10;
  if (conf_getvar(conf->conffile, "server", conf->servername, "min_pinginterval", tmpbuf, BUFSIZE)!=0)
    {
      sscanf(tmpbuf,"%i",&(conf->defaultping.min_pinginterval));
    }
  else
    conf->defaultping.min_pinginterval=1000;
  if (conf_getvar(conf->conffile, "server", conf->servername, "missdiff", tmpbuf, BUFSIZE)!=0)
    {
      sscanf(tmpbuf,"%i",&(conf->defaultping.missdiff));
    }
  else
    conf->defaultping.missdiff=5;
  /* Find out what address from which to send ICMP packets.
     If this is "any" or non-existent, the address is deduced from the
     kernel routing table. If an address is given in the configuration
     file, it must be "any", a IP address in dot notation or a resolvable host name */
  conf->defaultping.ping_source.sin_family=AF_INET;
  if ((!conf_getvar(conf->conffile,"server",conf->servername,"ping_source",tmpbuf,BUFSIZE)) ||
      !strcasecmp(tmpbuf,"any"))
    conf->defaultping.ping_source.sin_addr.s_addr=INADDR_ANY;
  else
    {
      if (!inet_aton(tmpbuf,&my_inaddr))
	{
	  if (!(listen_he=gethostbyname(tmpbuf)))
	    {
	      syslog(LOG_ERR,"Unknown ping_source address %s",tmpbuf);
	      closelog();
	      return 0;
	    }
	  else
	    {
	      conf->defaultping.ping_source.sin_family=listen_he->h_addrtype;
	      memcpy(&(conf->defaultping.ping_source.sin_addr), listen_he->h_addr_list[0],
		     sizeof(conf->defaultping.ping_source.sin_addr));
	    }
	}
      else
	memcpy(&(conf->defaultping.ping_source.sin_addr), &(my_inaddr), sizeof(conf->defaultping.ping_source.sin_addr));
    }

  if (conf->defaultping.ping_source.sin_addr.s_addr != INADDR_ANY)
    {
      syslog(LOG_NOTICE, "Using %s as source for ICMP ping", inet_ntoa(conf->defaultping.ping_source.sin_addr));
    }
  trace_init(conf->conffile, conf->servername);

  if (!conf_getvar(conf->conffile,"server",conf->servername,"accounting_id",tmpbuf2,BUFSIZE))
    strcpy(tmpbuf2, conf->progname);

  if (conf_getvar(conf->conffile,"server",conf->servername,"accounting_lib",tmpbuf,BUFSIZE))
    if ((conf->accounting_handle=acct_init(tmpbuf, tmpbuf2))==NULL)
      syslog(LOG_ERR, "acct_init(%s, %s): %s", tmpbuf, tmpbuf2, acct_last_error());

  if (conf_getvar(conf->conffile,"server",conf->servername,"stat_timelimit",tmpbuf2,BUFSIZE))
    sscanf(tmpbuf2, "%i", &(conf->stat_timelimit));
  else
    conf->stat_timelimit=60;

  if (conf_getvar(conf->conffile,"server",conf->servername,"stat_countlimit",tmpbuf2,BUFSIZE))
    sscanf(tmpbuf2, "%i", &(conf->stat_countlimit));
  else
    conf->stat_countlimit=3;

  if (conf_getvar(conf->conffile,"server",conf->servername,"stat_blockchain",tmpbuf2,BUFSIZE))
    strncpy(conf->stat_blockchain, tmpbuf2, sizeof(conf->stat_blockchain));
  else
    conf->stat_blockchain[0]='\0';

  if (conf_getvar(conf->conffile,"server",conf->servername,"stat_blocktime",tmpbuf2,BUFSIZE))
    sscanf(tmpbuf2, "%i", &(conf->stat_blocktime));
  else
    conf->stat_blocktime=900;

  if (conf_getvar(conf->conffile,"server",conf->servername,"stat_blockgc",tmpbuf2,BUFSIZE))
    sscanf(tmpbuf2, "%i", &(conf->stat_blockgc));
  else
    conf->stat_blockgc=3600;

  if (conf_getvar(conf->conffile,"server",conf->servername,"counterchain",tmpbuf2,BUFSIZE))
    strncpy(conf->counterchain, tmpbuf2, sizeof(conf->counterchain));
  else
    conf->counterchain[0]='\0';

  if (conf_getvar(conf->conffile,"server",conf->servername,"counterinterval",tmpbuf2,BUFSIZE))
    sscanf(tmpbuf2, "%i", &(conf->counter_interval));
  else
    conf->counter_interval = 0;

  if (conf_getvar(conf->conffile,"server",conf->servername,"rxidle",tmpbuf2,BUFSIZE))
    sscanf(tmpbuf2, "%i", &(conf->rxidle));
  else
    conf->rxidle = 0;

  if (conf_getvar(conf->conffile,"server",conf->servername,"txidle",tmpbuf2,BUFSIZE))
    sscanf(tmpbuf2, "%i", &(conf->txidle));
  else
    conf->txidle = 0;

  conf->idlenetworks = NULL;
  if (conf_getvar(conf->conffile,"server",conf->servername,"idlehosts",tmpbuf2,BUFSIZE))
    {
      splitstring(tmpbuf2, ',', &tmphosts);
      tmphosts2 = tmphosts;
      while (tmphosts2)
	{
	  tmpidlehost=NULL;
	  splitnum = splitstring(tmphosts2->name, '/', &tmpidlehost);
	  if (splitnum == 1 || splitnum == 2)
	    {
	      idlehost = (struct network *)malloc(sizeof(struct network));
	      if (!idlehost)
		{
		  freenamelist(&tmpidlehost);
		  break;
		}

	      inet_aton(tmpidlehost->name, &my_inaddr);
	      idlehost->network = ntohl(my_inaddr.s_addr);
	      if (splitnum == 2)
		{
		  if (strchr(tmpidlehost->next->name, '.'))
		    {
		      inet_aton(tmpidlehost->next->name, &my_inaddr);
		      idlehost->netmask = ntohl(my_inaddr.s_addr);
		    }
		  else
		    {
		      sscanf(tmpidlehost->next->name, "%i", &(netmask_cidr));
		      idlehost->netmask = 0;
		      for (i = 1; i <= netmask_cidr; i++)
			idlehost->netmask |= 1<<(32-i);
		    }
		}
	      else
		{
		  idlehost->netmask = 0xffffffff;
		}

	      idlehost->next = conf->idlenetworks;
	      conf->idlenetworks = idlehost;
	    }
	  freenamelist(&tmpidlehost);
	  tmphosts2 = tmphosts2->next;
	}
      freenamelist(&tmphosts);
    }

  if (conf_getvar(conf->conffile,"server",conf->servername,"savetime",tmpbuf2,BUFSIZE))
    sscanf(tmpbuf2, "%i", &alarmtime);
  else
    alarmtime = 0;

  return 1;
}

int main(int argc, char *argv[])
{
  struct config my_config;
  int command_server_socket;
  int sockopt;
  int r;

  if (((argc!=2) && (argc!=3) && (argc!=5)) || ((argc==5) && (strcmp(argv[3],"-l"))) ||
      ((argc==2) && strcmp(argv[1],"-V")))
    {
      fprintf(stderr, "Usage: %s <conffile> <servername> [ -l <filename> ]\n", argv[0]);
      fprintf(stderr, "\t %s -V\n", argv[0]);
      return RET_INVOKE;
    }
  if ((argc==2) && !strcmp(argv[1],"-V"))
    {
      printf("%s\n", versionstring(NULL,0));
      return 0;
    }
  memset(&my_config,0,sizeof(my_config));
  strncpy(my_config.servername, argv[2], CONFBSIZE);
  my_config.servername[CONFBSIZE-1]='\0';
  strncpy(my_config.conffile, argv[1], CONFBSIZE);
  my_config.conffile[CONFBSIZE-1]='\0';
  if (argc==5)
    strncpy(my_config.loadfile, argv[4], CONFBSIZE);
  else
    my_config.loadfile[0]='\0';

  my_config.loadfile[CONFBSIZE-1]='\0';

  if (!initialize(&my_config))
    {
      fprintf(stderr,"initialize() failed - see log file\n");
      return RET_INIT;
    }

  fprintf(stderr,"%s: Listening on %s:%d\n", my_config.servername, 
	  inet_ntoa(my_config.listen_address.sin_addr),
	  ntohs(my_config.listen_address.sin_port));
  if ((command_server_socket=socket(AF_INET,SOCK_STREAM,0))==-1)
    {
      syslog(LOG_ERR,"socket(): %m");
      return RET_SOCKET;
    }
  sockopt=1;
  if (setsockopt(command_server_socket,SOL_SOCKET,SO_REUSEADDR,
		 &sockopt,sizeof(sockopt))!=0)
    {
      syslog(LOG_ERR,"setsockopt(): %m");
      return RET_SOCKET;
    }
  if (bind(command_server_socket, (struct sockaddr *)&(my_config.listen_address),
	   sizeof(my_config.listen_address))==-1)
    {
      syslog(LOG_ERR, "bind(): %m");
      return RET_SOCKET;
    }

  /* Start listening to the socket */
  if (listen(command_server_socket,10)!=0)
    {
      syslog(LOG_ERR,"listen(): %m");
      return RET_SOCKET;
    }

  syslog(LOG_NOTICE,"iplogin2 starting (%s)",versionstring(NULL,0));
  syslog(LOG_NOTICE,"%s",params(&my_config));
  r=mainloop(&my_config, command_server_socket);

  if (strlen(my_config.pidfile))
    unlink(my_config.pidfile);
  closelog();
  close(command_server_socket);
  trace_quit();
  return (r?0:RET_GENERAL);
}
