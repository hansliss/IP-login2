#include <sys/time.h>
#include <sys/timeb.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include "autoconfig.h"
#include <hl.h>
#include "socketnode.h"
#include "commands.h"
#include "filterchains.h"
#include "arpping.h"
#include "icmpping.h"
#include "mymalloc.h"
#include "accounting.h"
#include "misc.h"

#include "engine.h"

#include "trace.h"

#if (HAVE_LIBWRAP == 1)
#include <tcpd.h>
#endif

#define BUFSIZE 8192

#define GC_PERIOD 2
#define LOOP_SLEEP 200
#define MISSSTATPERIOD 1

extern unsigned int alarmtime;

/*
  Check and authenticate a new incoming command server connection
  before handing it over to docommand().

  Parameters:
  'conffile' (in): Configuration file for this server
  'progname' (in): Program name, used as id in /etc/hosts.allow
  'csocket' (in): The accept():ed connection socket
  'servername' (in): Our server name for finding the server key
  'users' (in/out): The list of active users
  */

void handle_connection(struct config *conf, int csocket, usernode *users)
{
  struct sockaddr_in client_sa;
  char client_ip[16], clientname[1024];
  char local_key[128], remote_key[128];
  int namelen;
  namelist possible_clients=NULL;
  HLCRYPT_HANDLE h=NULL;
#if (HAVE_LIBWRAP == 1)
  struct request_info req;

  /* Check client with libwrap */
  request_init(&req, RQ_DAEMON, conf->progname, RQ_FILE, csocket, NULL);
  fromhost(&req);
  if (!hosts_access(&req))
    syslog(deny_severity, "connection from %s refused", eval_client(&req));
  else
    {
      /*      syslog(allow_severity, "connect from %s", eval_client(&req));*/
#endif
      /* Get peer IP address */
      namelen=sizeof(client_sa);
      if (getpeername(csocket,(struct sockaddr *)&client_sa,&namelen)!=0)
	syslog(LOG_ERR,"getpeername(): %m");
      else
	{
	  /* Print the IP address to a string for searching in the conffile */
	  strncpy(client_ip,(char *)inet_ntoa(client_sa.sin_addr),
		  sizeof(client_ip));
	  client_ip[sizeof(client_ip)-1]='\0';

	  /* Find out who this client is */
	  if (!conf_matchlist(conf->conffile,"client", "ip", client_ip,
			      &possible_clients))
	    syslog(LOG_ERR,
		   "%s: no matching client defined in configuration file",
		   client_ip);
	  else /* conf_matchlist */
	    {
	      /* Select only the FIRST matching client even if there
		 are more!! There shouldn't be more than one, anyway. */
	      strncpy(clientname, possible_clients->name, sizeof(clientname));
	      clientname[sizeof(clientname)-1]='\0';
		    
	      /* Get the server key from the conffile */
	      if (!conf_getvar(conf->conffile,"server",conf->servername,"key",
			       local_key,sizeof(local_key)))
		syslog(LOG_ERR,
		       "No server key is defined for %s",
		       conf->servername);
	      else /* server key */
		{
		  if (!conf_getvar(conf->conffile,"client",clientname,"key",
				   remote_key,sizeof(remote_key)))
		    syslog(LOG_ERR,
			   "No client key is defined for %s",clientname);
		  else /* client key */
		    {
		      /* Try to authenticate the client or fail silently */
		      if (hlcrypt_AuthServer(csocket, remote_key, local_key, &h))
			{
			  /* Receive and handle a command now, the client
			     is OK */
			  docommand(conf, csocket, clientname, users, h);
			  hlcrypt_freeHandle(&h);
			}
		    }
		}
	      freenamelist(&possible_clients);
	    }
	}
#if (HAVE_LIBWRAP == 1)
    }
#endif
  /*  shutdown(csocket, 2);*/
  close(csocket);
}

/*
  Retrive TX and RX counters for all the users
  */
void retrieve_counters(struct config *conf, usernode users)
{
  counternode counters=NULL, tmpcounter;
  usernode thisuser=users;
  unsigned int interval;
  time_t logged_in;

  if (!strlen(conf->counterchain))
    return;
  while (thisuser)
    {
      if (!(tmpcounter=(counternode)malloc(sizeof(struct counternode_s))))
	{
	  while(counters)
	    {
	      tmpcounter=counters->next;
	      free(counters);
	      counters=tmpcounter;
	    }
	  syslog(LOG_ERR, "Memory allocation error in retrieve_counters()");
	  return;
	}
      memcpy(&(tmpcounter->address), &(thisuser->address), sizeof(thisuser->address));
      tmpcounter->rxcounter=0;
      tmpcounter->txcounter=0;
      tmpcounter->next=counters;
      counters=tmpcounter;
      thisuser=thisuser->next;
    }
  if (fchain_getcounters(conf->counterchain, counters))
    {
      tmpcounter=counters;
      while (tmpcounter)
	{
	  thisuser=users;
	  while (thisuser)
	    {
	      if (!memcmp(&(thisuser->address), &(tmpcounter->address), sizeof(tmpcounter->address)))
		{
		  interval = conf->counter_interval;
                 
		  time(&logged_in);
		  logged_in-=thisuser->added;

		  if ((unsigned int)logged_in < interval)
		    interval = (unsigned int)logged_in;

		  if (interval == 0)
		    interval = 1;

		  thisuser->rxkbps=8*((long double)(tmpcounter->rxcounter - thisuser->rxcounter)/1024.0)/interval;
		  thisuser->txkbps=8*((long double)(tmpcounter->txcounter - thisuser->txcounter)/1024.0)/interval;

		  if (thisuser->rxcounter == tmpcounter->rxcounter)
		    thisuser->rxidle += interval;
		  else
		    thisuser->rxidle = 0;

		  if (thisuser->txcounter == tmpcounter->txcounter)
		    thisuser->txidle += interval;
		  else
		    thisuser->txidle = 0;

		  thisuser->rxcounter=tmpcounter->rxcounter;
		  thisuser->txcounter=tmpcounter->txcounter;
		}
	      thisuser=thisuser->next;
	    }
	  tmpcounter=tmpcounter->next;
	}
    }
  while(counters)
    {
      tmpcounter=counters->next;
      free(counters);
      counters=tmpcounter;
    }
}

/*
  Traverse the list of users and send ping packets of appropriate types
  to them all.

  Parameters:
  'rawsockets' (in/out): A list of currently open sockets, one for each
  ethernet interface and each user type.
  'user' (in): All the users
  'ident' (in): An identity for ICMP echo request
  */
void send_pings(socketnode *rawsockets, usernode users, int ident)
{
  static char tmpbuf[BUFSIZE];
  usernode tmpuser=users;
  while (tmpuser)
    {
      switch (tmpuser->user_type)
	{
	case USER_TYPE_ARPPING:
	  sprintf(tmpbuf,"ARP request to %s",inet_ntoa(tmpuser->address));
	  trace_msg(tmpbuf);
	  mymalloc_pushcontext("send_arpping()");
	  send_arpping(rawsockets, tmpuser);
	  mymalloc_popcontext();
	  tmpuser->last_sent=time(NULL);
	  break;
	case USER_TYPE_PING:
	  sprintf(tmpbuf,"ICMP echo request to %s",inet_ntoa(tmpuser->address));
	  trace_msg(tmpbuf);
	  mymalloc_pushcontext("send_icmpping()");
	  send_icmpping(rawsockets, tmpuser, ident);
	  mymalloc_popcontext();
	  tmpuser->last_sent=time(NULL);
	  break;
	case USER_TYPE_NONE:
	  break;
	default:
	  syslog(LOG_ERR,"User %s has illegal type %d",
		 inet_ntoa(tmpuser->address),
		 tmpuser->user_type);
	  tmpuser->user_type=USER_TYPE_NONE;
	  break;
	}
      tmpuser=tmpuser->next;
    }
}

/*
  Receive and handle all pending replies on all the open
  sockets.

  Parameters:
  'allsockets' (in): A list of currently open sockets
  'users' (in): All the users
  'ident' (in): An identity for ICMP echo reply
  */
void receive_replies(socketnode allsockets, usernode users, int ident, int timeout)
{
  fd_set myfdset;
  int maxsock=-1, i;
  socketnode tmpsock;
  struct timeval select_timeout;
  static unsigned char packet[4096];
  unsigned char from[16384];
  int alen;

#if 0
  static char tmpbuf[BUFSIZE];
  long nbytes;
  tmpsock=allsockets;
  while (tmpsock)
    {
      ioctl(tmpsock->socket, FIONREAD, &nbytes);
      if (nbytes>0)
	{
	  sprintf(tmpbuf, "%ld bytes waiting on fd %d",nbytes, tmpsock->socket);
	  trace_msg(tmpbuf);
	}
      tmpsock=tmpsock->next;
    }
#endif

  /* Loop until select() says 'no' */
  while (1)
    {
      select_timeout.tv_sec=timeout/1000;
      select_timeout.tv_usec=1000*(timeout%1000);
      /* Initialize an fd_set with all the fd:s we are interested in */
      FD_ZERO(&myfdset);
      tmpsock=allsockets;
      while (tmpsock)
	{
	  FD_SET(tmpsock->socket, &myfdset);
	  if (tmpsock->socket > maxsock)
	    maxsock=tmpsock->socket;
	  tmpsock=tmpsock->next;
	}

      /* Check if there is anything to receive */
      if (select(maxsock+1, &myfdset, NULL, NULL, &select_timeout)>0)
	{
	  for (i=0; i<(maxsock+1); i++)
	    if (FD_ISSET(i, &myfdset))
	      {
		/* fprintf(stderr,"Packet received on fd %d\n", i);*/

		/* Receive a packet */
		alen=sizeof(from);
		if (recvfrom(i, packet, sizeof(packet), 0,
			     (struct sockaddr *)&from, &alen)<0)
		  syslog(LOG_ERR, "recvfrom(): %m");
		else /* recvfrom */
		  {
		    /* Hand this packet over to recv_arpreply */
		    if (!recv_arpreply(packet, sizeof(packet),
				       (struct sockaddr_ll *)from, users))
		      {
			/* ..or to recv_icmpreply if that fails */
			recv_icmpreply(packet, sizeof(packet), 
				       (struct sockaddr_in *)from, users,
				       ident);
		      }
		  }
	      }
	}
      else /* select */
	break;
    } /* while */
  return;
}

/* Ugly: If parameters are non-NULL, just save them to our local vars,
   otherwise save the state to the file, if a filename is available */
void savestate_helper(int do_quit, char *n, usernode *s, socketnode *a, void *h)
{
  static usernode *users=NULL;
  static char *filename=NULL;
  static socketnode *allsockets=NULL;
  static void *accounting_handle=NULL;
  socketnode tmpsock;
  if (n && s && a)
    {
      users=s;
      filename=n;
      allsockets=a;
      accounting_handle=h;
    }
  else
    {
      if (filename)
	do_save_state(-1, filename, *users, NULL);
      if (do_quit)
	{
	  do_reset(users);
	  while (*allsockets)
	    {
	      tmpsock=*allsockets;
	      (*allsockets)=(*allsockets)->next;
	      close(tmpsock->socket);
	      free(tmpsock);
	    }
	  syslog(LOG_NOTICE,"Exiting");
	  if (accounting_handle)
	    acct_cleanup(accounting_handle);
	  closelog();
	  exit(0);
	}
    }
}
  
void savestate(int s)
{
  int do_quit=0;
  if ((s==SIGUSR2) || (s==SIGTERM))
    do_quit=1;

  savestate_helper(do_quit, NULL, NULL, NULL, NULL);
  if (s == SIGALRM)
    {
      signal(SIGALRM, savestate);
      alarm(alarmtime);
    }
  else
    signal(SIGUSR1, savestate);
}

void removeuser(usernode *users, usernode user, struct config *conf, char *reason)
{
  char tmpbuf[BUFSIZE];
  namelist tmplist;
  time_t elapsed;

  /* Remove this user from all filter chains */
  tmplist=user->filter_chains;
  while (tmplist)
    {
      fchain_delrule(user->address, tmplist->name);
      tmplist=tmplist->next;
    }
  /* Tell the world! */
  time(&elapsed);
  elapsed-=user->added;

  strcpy(tmpbuf, ctime(&(user->added)));
  chop(tmpbuf);

  syslog(LOG_NOTICE, "%s: deleting %s, %s after %02d.%02d.%02d. Logged in %s. %u responses received",
	 reason,
	 inet_ntoa(user->address),
	 user->account,
	 (int)(elapsed/3600),
	 (int)(elapsed%3600)/60,
	 (int)(elapsed%60),
	 tmpbuf,
	 user->hits
	 );

  if (strlen(conf->stat_blockchain) && user->block_installed)
    fchain_delrule(user->address, conf->stat_blockchain);

  /* ..and remove the user from our list */
  delUser(users,&user->address, conf->accounting_handle);
}

/* See the header file */
int mainloop(struct config *conf, int command_server_socket)
{
  int addr_len;
  int ready=0;
  int scount, lastcount=0;
  unsigned int number_to_ping;

  struct sockaddr_in remote_addr;
  int csocket;
  struct timeval select_timeout;
  fd_set myfdset;
  int ident;
  usernode users=NULL;
  time_t missstat_last=0;
  int missstat_count=0;

  time_t counters_last=0;

  time_t stat_gc_last=0;

  time_t now=0, lastgc=0;
  struct timeb last_accept={0,0}, lastcycle, thiscycle;

  socketnode allsockets=NULL, tmpsock;

  static char tmpbuf[BUFSIZE];
  namelist tmplist, tmplist2;
  usernode tmpuser, tmpuser2, tmpuser3;

  mymalloc_pushcontext("mainloop()");
  fchain_init();
  tmplist=NULL;
  if (conf_getvar(conf->conffile,"server",conf->servername,"flush_on_start",tmpbuf,sizeof(tmpbuf)) &&
      splitstring(tmpbuf,',',&tmplist)>0)
    {
      tmplist2=tmplist;
      while (tmplist2)
	{
	  fchain_flush(tmplist2->name);
	  tmplist2=tmplist2->next;
	}
      freenamelist(&tmplist);
    }

  ident=getpid()&0xFFFF;

  /* Don't stop on SIGPIPE */
  signal(SIGPIPE, SIG_IGN);

  /* If 'loadfile' is non-empty, load state from the file */
  if (strlen(conf->loadfile)>0)
    do_load_state(-1, conf, conf->loadfile, &users, &(conf->defaultping.ping_source), conf->accounting_handle, NULL);

  /* Prepare for saving functionality - just save the filename */
  savestate_helper(0, conf->loadfile, &users, &allsockets, conf->accounting_handle);
  signal(SIGUSR1, savestate);
  signal(SIGUSR2, savestate);
  signal(SIGTERM, savestate);
  if (alarmtime != 0)
    {
      signal(SIGALRM, savestate);
      alarm(alarmtime);
    }
  ftime(&lastcycle);

  time(&counters_last);

  while (!ready)
    {
      ftime(&thiscycle);
      if (((unsigned long)(1000*(thiscycle.time-last_accept.time) + 
			   thiscycle.millitm - last_accept.millitm)) > 
	  conf->accept_interval)
	{
#ifdef BIGTRACE
	  trace_msg("Checking for control connections");
#endif
	  /********* Check for an incoming command server connection ********/
	  FD_ZERO(&myfdset);
	  FD_SET(command_server_socket, &myfdset);
	  select_timeout.tv_sec=conf->accept_timeout/1000;
	  select_timeout.tv_usec=1000*(conf->accept_timeout%1000);
	  if (select(command_server_socket+1, &myfdset, NULL, NULL,
		     &select_timeout)!=-1)
	    {
	      if (FD_ISSET(command_server_socket, &myfdset))
		{
		  addr_len=sizeof(remote_addr);
		  if ((csocket=accept(command_server_socket,
				      (struct sockaddr *)&remote_addr,
				      &addr_len))!=-1)
		    handle_connection(conf, csocket, &users);
		  else if (errno != EINTR)
		    syslog(LOG_ERR,"accept(): %m");
		}
	    }
	  else
	    if (errno != EINTR)
	      syslog(LOG_ERR, "engine::mainloop(): select(): %m");
	  last_accept=thiscycle;
	}

#ifdef BIGTRACE
      trace_msg("Checking for replies");
#endif
      /********* Receive any pending PING replies *********/
      receive_replies(allsockets, users, ident, 250);

      scount=0;
      tmpuser=users;

      time(&now);
#if 0
      if (((unsigned long)(now-lastgc)) > GC_PERIOD)
#else
	if (1)
#endif
	  {
	    while (tmpuser)
	      {
		/* Check first if we consider the last PING missed */
		if (tmpuser->last_checked_send != tmpuser->last_sent)
		  {
		    if (tmpuser->last_received <
			(tmpuser->last_sent - conf->defaultping.missdiff))
		      {
			tmpuser->missed++;
			tmpuser->last_checked_send=tmpuser->last_sent;
			missstat_count++;
		      }
		    else
		      {
			if (tmpuser->last_received!=0)
			  {
			    tmpuser->missed=0;
			    tmpuser->hits++;
			    tmpuser->last_checked_send=tmpuser->last_sent;
			  }
		      }
		  }

		/* If missed one too many times.. */
		if (tmpuser->missed > conf->defaultping.maxmissed)
		  {
		    missstat_count-=tmpuser->missed;
		    if (missstat_count<0)
		      missstat_count=0;

		    removeuser(&users, tmpuser, conf, "Timeout");

		    /* ..then start over instead of trying to continue
		       in the modified list */
		    tmpuser=users;
		    scount=0;
		  }
		else /* if (..missed..) */
		  {
		    if (strlen(conf->stat_blockchain) && (tmpuser->block_installed) &&
			((now - tmpuser->block_installed) > conf->stat_blocktime))
		      {
			fchain_delrule(tmpuser->address, conf->stat_blockchain);
			tmpuser->block_installed=0;
			tmpuser->statmit_count=0;
		      }
		    tmpuser=tmpuser->next;
		    scount++;
		  }
	      } /* while (tmpuser) */
	    if (scount!=lastcount)
	      {
		recalc(&(conf->defaultping), conf->logout_timeout, scount);
		lastcount=scount;
	      }
	  
	    /* ..and remember when we did this */
	    lastgc=now;
	  } /* while (...GC_PERIOD...) */

      if (strlen(conf->stat_blockchain) && ((now - stat_gc_last) > conf->stat_blockgc))
	{
	  fchain_flush(conf->stat_blockchain);
	  stat_gc_last=now;
	}

      if ((now - missstat_last) > (MISSSTATPERIOD * 60))
	{
	  syslog(LOG_DEBUG, "Missed %d replies in the last %d minute%s", missstat_count, MISSSTATPERIOD, (MISSSTATPERIOD>1)?"s":"");
	  missstat_count=0;
	  missstat_last=now;



	}
      if (conf->counter_interval && (now - counters_last) > conf->counter_interval)
	{
	  retrieve_counters(conf, users);
	  counters_last=now;

	  tmpuser3=users;
	  while (tmpuser3)
	    {
	      if (tmpuser3->idle_logout && ((conf->rxidle && tmpuser3->rxidle >= conf->rxidle)
					    || (conf->txidle && tmpuser3->txidle >= conf->txidle)))
		{
		  removeuser(&users, tmpuser3, conf, "Idle");
		  scount=0;
		  recalc(&(conf->defaultping), conf->logout_timeout, scount);
		  lastcount=scount;
		  tmpuser3 = users;
		  continue;
		}

	      tmpuser3=tmpuser3->next;
	    }
	}

      trace_msg("Sending requests");
      
      /* Finally, send out all those ping packets */
      ftime(&thiscycle);

      if (conf->defaultping.pinginterval)
	number_to_ping=1000 * (1000 * (thiscycle.time - lastcycle.time) + 
			       thiscycle.millitm - lastcycle.millitm) /
	  conf->defaultping.pinginterval;
      else
	number_to_ping=0;
      if (number_to_ping>0)
	{
	  /* Extract 'number_to_ping' users from the beginning of the list */
	  tmpuser=users;
	  tmpuser2=NULL;
	  while (users && (number_to_ping--))
	    {
	      tmpuser2=users;
	      users=users->next;
	    }
	  if (tmpuser2)
	    tmpuser2->next=NULL;

	  /* Send pings only to those users */
	  send_pings(&allsockets, tmpuser, ident);

	  /* And then link them onto the end of the list */
	  if (!users)
	    users=tmpuser;
	  else
	    {
	      tmpuser2=users;
	      while (tmpuser2->next)
		tmpuser2=tmpuser2->next;
	      tmpuser2->next=tmpuser;
	    }
	  lastcycle=thiscycle;
	}
      usleep(LOOP_SLEEP);
    } /* while (!ready) */
  /* This will not happen in this version */
  do_reset(&users);
  while (allsockets)
    {
      tmpsock=allsockets;
      allsockets=allsockets->next;
      close(tmpsock->socket);
      free(tmpsock);
    }
  mymalloc_popcontext();
  return 1;
}

  
