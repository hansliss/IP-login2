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

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "varlist.h"
#include "filterchains.h"
#include "filterchains2.h"
#include <iptables.h>

namelist used_chains=NULL;

#define BUFSIZE 8192

void parsechainspec(char *spec, char **table, char **chain, char **direction, char **target)
{
  static char t[BUFSIZE], c[BUFSIZE], dir[BUFSIZE], targ[BUFSIZE];
  namelist tmplist=NULL;
  char *p1;
  (*table)=NULL;
  (*chain)=NULL;
  (*direction)=NULL;
  (*target)=NULL;
  if (splitstring(spec, ':', &tmplist)==2)
    {
      strncpy(t, tmplist->name, sizeof(t));
      t[sizeof(t)-1]='\0';
      (*table)=t;
      spec=tmplist->next->name;
    }

  strncpy(c, spec, sizeof(c));
  c[sizeof(c)-1]='\0';
  (*chain)=c;
  if ((p1=strchr(c, '/'))!=NULL)
    {
      (*p1++)='\0';
      strncpy(dir, p1, sizeof(dir));
      dir[sizeof(dir)-1]='\0';
      (*direction)=dir;
    }
  if ((p1=strchr(c, '>'))!=NULL)
    {
      (*p1++)='\0';
      strncpy(targ, p1, sizeof(targ));
      targ[sizeof(targ)-1]='\0';
      (*target)=targ;
    }
  if ((p1=strchr(dir, '>'))!=NULL)
    {
      (*p1++)='\0';
      strncpy(targ, p1, sizeof(targ));
      targ[sizeof(targ)-1]='\0';
      (*target)=targ;
    }


  freenamelist(&tmplist);
}

/* Flush a given chain */
void fchain_flush(char *spec)
{
  char *table, *chain, *direction, *target;
  int ret;
  parsechainspec(spec, &table, &chain, &direction, &target);
  if (!table)
    table="filter";

  syslog(LOG_INFO,"Flushing table %s, chain %s", table, chain);

  ret=iptables_flush_chain(table, chain);
}

/* Add a rule to a named chain. Create the chain if it
   doesn't exist, and remember that it is our own chain */
void fchain_addrule(struct in_addr address, char *spec)
{
  char *table, *chain, *direction, *target;
  static char chainspec[BUFSIZE];
  int ret;
  namelist tmplist2=used_chains;
  struct in_addr twofiftyfive, zero;
  inet_aton("255.255.255.255", &twofiftyfive);
  inet_aton("0.0.0.0", &zero);

  parsechainspec(spec, &table, &chain, &direction, &target);
  if (!table)
    table="filter";

  if (!target)
    target="ACCEPT";

  if (!direction)
    direction="s";

  sprintf(chainspec, "%.32s:%.32s", table, chain);

  while (tmplist2 && (strcmp(tmplist2->name, chainspec)))
    tmplist2 = tmplist2->next;
  if (!tmplist2)
    {
      if ((ret=iptables_create_chain(table,chain))==0)
	  syslog(LOG_ERR,"iptables_create_chain(%s): %m", chainspec);
      else
	{
	  syslog(LOG_INFO,"Created chain %s", chainspec);
	  addname(&used_chains, chainspec);
	}
    }

  /*  syslog(LOG_INFO,"Adding filter line for %s to table %s, chain %s, direction %s, target %s", inet_ntoa(address), table, chain, direction, target);*/

  if (!strcmp(direction, "s") || !strcmp(direction, "b"))
    iptables_add_line(table, chain, &address, &twofiftyfive, &zero, &zero, target);

  if (!strcmp(direction, "d") || !strcmp(direction, "b"))
    iptables_add_line(table, chain, &zero, &zero, &address, &twofiftyfive, target);
}

/* Remove a given rule from a named chain if it exists */
void fchain_delrule(struct in_addr address, char *spec)
{
  char *table, *chain, *direction, *target;
  struct in_addr twofiftyfive, zero;
  inet_aton("255.255.255.255", &twofiftyfive);
  inet_aton("0.0.0.0", &zero);

  parsechainspec(spec, &table, &chain, &direction, &target);
  if (!table)
    table="filter";

  if (!target)
    target="ACCEPT";

  if (!direction)
    direction="s";

  /*  syslog(LOG_INFO,"Removing filter line for %s to table %s, chain %s, direction %s, target %s", inet_ntoa(address), table, chain, direction, target);*/

  if (!strcmp(direction, "s") || !strcmp(direction, "b"))
    iptables_delete_line(table, chain, &address, &twofiftyfive, &zero, &zero, target);

  if (!strcmp(direction, "d") || !strcmp(direction, "b"))
    iptables_delete_line(table, chain, &zero, &zero, &address, &twofiftyfive, target);

}

/* Flush all the chains for which we are responsible */
void fchain_unloadall()
{
  namelist tmplist=used_chains;
  while (tmplist)
    {
      fchain_flush(tmplist->name);
      tmplist=tmplist->next;
    }
  freenamelist(&used_chains);
}

/*
  Retrieve RX and TX byte counters
  */
int fchain_getcounters(char *spec, counternode requested_counters)
{
  char *table, *chain, *direction, *target;
  if (!requested_counters)
    return 0;
  parsechainspec(spec, &table, &chain, &direction, &target);
  if (!table)
    table="filter"; 
  return iptables_read_counters(table, chain, requested_counters);
}

/* Init this system */
void fchain_init()
{
  used_chains=NULL;
  iptables_init();
}


