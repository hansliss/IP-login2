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

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/timeb.h>
#include "usernode.h"
#include "accounting.h"
#include "trie.h"

/*
  We try to keep the list in address order, strictly for cosmetical
  reasons.
  */
usernode addUser(struct trie *nodes, struct config *conf, char *account, char *session_id,
		 int user_type, struct in_addr *address,
		 int ifindex, char *ifname, struct in_addr *source,
		 namelist chains,
		 time_t added, void *accounting_handle)
{
  usernode new_user;
  struct timeb tb;
  unsigned int useraddress;
  struct network *tmpidlehost;

      if (!(new_user=(usernode)malloc(sizeof(*new_user))))
	{
	  syslog(LOG_ERR,"malloc(): %m");
	  return NULL;
	}
      else
	{
	  if (!(new_user->account=(char*)malloc(strlen(account)+1)))
	    {
	      syslog(LOG_ERR,"malloc(): %m");
	      free(new_user);
	      return NULL;
	    }
	  else
	    {
	      strcpy(new_user->account, account);
	      new_user->user_type=user_type;
	      new_user->ifindex=ifindex;
	      memset(new_user->ifname, 0, sizeof(new_user->ifname));
	      strncpy(new_user->ifname, ifname, sizeof(new_user->ifname-1));
	      memcpy(&(new_user->address),address, sizeof(struct in_addr));
	      memcpy(&(new_user->source_address),source,
		     sizeof(struct in_addr));
	      new_user->filter_chains=chains;
	      new_user->missed=0;
	      new_user->hits=0;
	      new_user->added=added;
	      new_user->last_received=0;
	      new_user->last_sent=0;
	      new_user->last_stat=0;
	      new_user->statmit_count=0;
	      new_user->rxcounter=0;
	      new_user->txcounter=0;
	      new_user->rxkbps=0;
	      new_user->txkbps=0;
	      new_user->rxidle=0;
	      new_user->txidle=0;
	      new_user->idle_logout=0;

	      tmpidlehost = conf->idlenetworks;
	      while (tmpidlehost && !new_user->idle_logout)
		{
		  useraddress = ntohl(new_user->address.s_addr);

		  if ((useraddress & tmpidlehost->netmask) == (tmpidlehost->network & tmpidlehost->netmask))
		    new_user->idle_logout=1;

		  tmpidlehost = tmpidlehost->next;
		}

	      new_user->block_installed=0;
	      new_user->ll_address_set=-1;
	      ftime(&tb);
	      if (!session_id)
		sprintf(new_user->session_id,"%08x%08x",
			(int)tb.millitm&0xffffffff,
			(int)getpid()&0xffffffff);
	      else
		{
		  strncpy(new_user->session_id, session_id, 16);
		  new_user->session_id[16]='\0';
		}

	      if (accounting_handle)
		acct_login(accounting_handle, new_user->account, new_user->session_id);
	      trie_put(nodes, (t_key)htonl(address->s_addr), (void *)new_user);
	      return new_user;
	    }
	}
}

usernode findUser(struct trie *nodes, struct in_addr *address)
{
  usernode tmpuser;
  if (trie_get(nodes, (t_key)htonl(address->s_addr), (void *)&(tmpuser)))
    return NULL;
  else
    return tmpuser;
}

usernode findUser_account(struct trie *nodes, char *account)
{
  usernode tmpnode, result=NULL;
  trietrav_handle h=NULL;
  unsigned int key;

  trietrav_init(&h, nodes, 0);
  while (trietrav_next(&h, &key, (void *)&(tmpnode), NULL))
    if (!strcasecmp(tmpnode->account, account))
      {
	result=tmpnode;
	trietrav_cleanup(&h);
	break;
      }
  return result;
}

/*
  Find the node to delete. If found, save it to 'tmpuser'
  and relink the list past it, then release it.
  */
void delUser(struct trie *nodes, struct in_addr *address, void *accounting_handle)
{
  usernode tmpuser;
  if (!trie_get(nodes, (t_key)htonl(address->s_addr), (void *)&((tmpuser))))
    {
      trie_remove(nodes, (t_key)htonl(address->s_addr));
      if (accounting_handle)
	acct_logout(accounting_handle, tmpuser->account, tmpuser->session_id);
      free(tmpuser->account);
      freenamelist(&(tmpuser->filter_chains));
      free(tmpuser);
    }
}

void freeUserList(struct trie *nodes, void *accounting_handle)
{
  ;
}

