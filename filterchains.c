#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <syslog.h>

#include <varlist.h>
#include "filterchains.h"
#include "filterchains2.h"
#include <iptables.h>

namelist used_chains=NULL;

#define BUFSIZE 8192

/* Flush a given chain */
void fchain_flush(char *chain)
{
  char *table = "filter", *actchain=chain;
  int ret;
  namelist tmplist=NULL;

  if (splitstring(chain, ':', &tmplist)==2)
    {
      table=tmplist->name;
      actchain=tmplist->next->name;
    }

  ret=iptables_flush_chain(table, actchain);

  freenamelist(&tmplist);
}

/* Add a rule to a named chain. Create the chain if it
   doesn't exist, and remember that it is our own chain */
void fchain_addrule(struct in_addr address, char *chain)
{
  char *table = "filter", *actchain=chain;
  int ret;
  namelist tmplist=NULL, tmplist2=used_chains;

  if (splitstring(chain, ':', &tmplist)==2)
    {
      table=tmplist->name;
      actchain=tmplist->next->name;
    }

  while (tmplist2 && (strcmp(tmplist2->name, chain)))
    tmplist2 = tmplist2->next;
  if (!tmplist2)
    {
      if ((ret=iptables_create_chain(table,actchain))==0)
	  syslog(LOG_ERR,"iptables_create_chain(%s): %m", chain);
      else
	{
	  syslog(LOG_INFO,"Created chain %s", chain);
	  addname(&used_chains, chain);
	}
    }

  syslog(LOG_INFO,"Adding filter line for %s to chain %s", inet_ntoa(address), chain);
  ret=iptables_add_line(table, actchain, &address);

  freenamelist(&tmplist);
}

/* Remove a given rule from a named chain if it exists */
void fchain_delrule(struct in_addr address, char *chain)
{
  char *table = "filter", *actchain=chain;
  int ret;
  namelist tmplist=NULL;

  if (splitstring(chain, ':', &tmplist)==2)
    {
      table=tmplist->name;
      actchain=tmplist->next->name;
    }

  ret=iptables_delete_line(table, actchain, &address);

  freenamelist(&tmplist);
}

/*
  Add a blocking TCP rule to the chain 'chain' (in) blocking all tcp traffic from the
  address 'address' (in).
  */
void fchain_addblock(struct in_addr address, char *chain)
{
  char *table = "filter", *actchain=chain;
  int ret;
  namelist tmplist=NULL, tmplist2=used_chains;

  if (splitstring(chain, ':', &tmplist)==2)
    {
      table=tmplist->name;
      actchain=tmplist->next->name;
    }

  while (tmplist2 && (strcmp(tmplist2->name, chain)))
    tmplist2 = tmplist2->next;
  if (!tmplist2)
    {
      if ((ret=iptables_create_chain(table,actchain))==0)
	  syslog(LOG_ERR,"iptables_create_chain(%s): %m", chain);
      else
	{
	  syslog(LOG_INFO,"Created chain %s", chain);
	  addname(&used_chains, chain);
	}
    }

  syslog(LOG_INFO,"Adding block for %s to chain %s", inet_ntoa(address), chain);
  ret=iptables_add_block(table, actchain, &address);

  freenamelist(&tmplist);
}

/*
  Delete a blocking rule from the chain 'chain' (in), for the
  address 'address' (in) or fail silently if none exists.
  */
void fchain_delblock(struct in_addr address, char *chain)
{
  char *table = "filter", *actchain=chain;
  int ret;
  namelist tmplist=NULL;

  if (splitstring(chain, ':', &tmplist)==2)
    {
      table=tmplist->name;
      actchain=tmplist->next->name;
    }

  syslog(LOG_INFO,"Removing block for %s from chain %s", inet_ntoa(address), chain);
  ret=iptables_delete_block(table, actchain, &address);

  freenamelist(&tmplist);
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

/* Init this system */
void fchain_init()
{
  used_chains=NULL;
  iptables_init();
}


