#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/timeb.h>
#include "usernode.h"
#include "accounting.h"

/*
  We try to keep the list in address order, strictly for cosmetical
  reasons.
  */
usernode addUser(usernode *l, char *account, char *session_id,
		 int user_type, struct in_addr *address,
		 int ifindex, char *ifname, struct in_addr *source,
		 namelist chains,
		 time_t added, void *accounting_handle)
{
  usernode new_user;
  struct timeb tb;
  if (!(*l) || ((*l)->address.s_addr > address->s_addr))
    {
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
	      strncpy(new_user->ifname, ifname, sizeof(new_user->ifname));
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
	      new_user->block_installed=0;
	      new_user->ll_address_set=-1;
	      new_user->next=(*l);
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
	      (*l)=new_user;
	      return new_user;
	    }
	}
    }
  else
    return addUser(&((*l)->next), account, session_id, user_type, address,
		      ifindex, ifname, source, chains, added, accounting_handle);
}

/*
  This function is not written to depend on the order of the list
  because there's no point, and the order could change anyway.
  */
usernode findUser(usernode l, struct in_addr *address)
{
  usernode tmpuser=l;
  while (tmpuser && (memcmp(&(tmpuser->address),
			       address, sizeof(struct in_addr))!=0))
    tmpuser=tmpuser->next;
  return tmpuser;
}

usernode findUser_account(usernode l, char *account)
{
  usernode tmpuser=l;
  while (tmpuser && (strcasecmp(tmpuser->account, account)!=0))
    tmpuser=tmpuser->next;
  return tmpuser;
}

/*
  Find the node to delete. If found, save it to 'tmpuser'
  and relink the list past it, then release it.
  */
void delUser(usernode *l, struct in_addr *address, void *accounting_handle)
{
  usernode tmpuser;
  if (!(*l))
    return;
  else if (!memcmp(&((*l)->address), address, sizeof(struct in_addr)))
    {
      tmpuser=(*l);
      (*l)=(*l)->next;
      if (accounting_handle)
	acct_logout(accounting_handle, tmpuser->account, tmpuser->session_id);
      free(tmpuser->account);
      freenamelist(&(tmpuser->filter_chains));
      free(tmpuser);
    }
  else
    delUser(&((*l)->next), address, accounting_handle);
}

void freeUserList(usernode *l, void *accounting_handle)
{
  if (!(*l))
    return;
  else
    {
      freeUserList(&((*l)->next), accounting_handle);
      if (accounting_handle)
	acct_logout(accounting_handle, (*l)->account, (*l)->session_id);
      free((*l)->account);
      freenamelist(&((*l)->filter_chains));
      free(*l);
      (*l)=NULL;
    }
}

