#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "autoconfig.h"
#include <hl.h>
#include "usernode.h"
#include "filterchains.h"
#include "find_interface.h"
#include "misc.h"
#include "mymalloc.h"
#include "accounting.h"

#define BUFSIZE 8192
#define READ_TIMEOUT 700

/*
  Note: All client replies using 'hlcrypt' are preceded by the number of
  strings sent, sent as a string.
  */

typedef void (*command_handler)(int csocket, namelist parms, usernode *users, struct config *conf);
/*** Protos ***/
void add_user(int csocket, namelist parms, usernode *users, struct config *conf);
void send_stat(int csocket, namelist parms, usernode *users, struct config *conf);
void do_check(int csocket, namelist parms, usernode *users, struct config *conf);
void del_user(int csocket, namelist parms, usernode *users, struct config *conf);
void reload_chains(int csocket, namelist parms, usernode *users, struct config *conf);
void printhelp(int csocket, namelist parms, usernode *users, struct config *conf);
void dump_state(int csocket, namelist parms, usernode *users, struct config *conf);
void reset(int csocket, namelist parms, usernode *users, struct config *conf);
void quit(int csocket, namelist parms, usernode *users, struct config *conf);
void save_state(int csocket, namelist parms, usernode *users, struct config *conf);
void load_state(int csocket, namelist parms, usernode *users, struct config *conf);
void return_count(int csocket, namelist parms, usernode *users, struct config *conf);
void return_rss(int csocket, namelist parms, usernode *users, struct config *conf);
void return_vsize(int csocket, namelist parms, usernode *users, struct config *conf);
void do_memdebug(int csocket, namelist parms, usernode *users, struct config *conf);
void do_addblock(int csocket, namelist parms, usernode *users, struct config *conf);
void do_delblock(int csocket, namelist parms, usernode *users, struct config *conf);

#define COMMAND_ADD 1
#define COMMAND_STAT 2
#define COMMAND_DEL 3
#define COMMAND_RELOAD 4
#define COMMAND_HELP 5
#define COMMAND_DUMP 6
#define COMMAND_RESET 7
#define COMMAND_QUIT 8
#define COMMAND_SAVESTATE 9
#define COMMAND_LOADSTATE 10
#define COMMAND_COUNT 11
#define COMMAND_RSS 12
#define COMMAND_VSIZE 13
#define COMMAND_MEMDEBUG 14
#define COMMAND_ADDBLOCK 15
#define COMMAND_DELBLOCK 16
#define COMMAND_CHECK 17
#define COMMAND_UNKNOWN -1
#define COMMAND_ARGS -2
#define COMMAND_PERMS -3

struct commandtabnode {
  char *name;
  int token;
  int args;
  command_handler fcall;
  char *usage;
} commandtab[]=
  {
    {"add",	COMMAND_ADD,	3, add_user,
     "Add a new address:\tadd <address> <account> <list of chains>"},
    {"stat",	COMMAND_STAT,	1, send_stat,
     "Get stats:\t\tstat <address>"},
    {"check",	COMMAND_CHECK,	1, do_check,
     "Check:\t\t\tcheck <address>"},
    {"del",	COMMAND_DEL,	1, del_user,
     "Delete an address:\tdel <address>"},
    {"reload",	COMMAND_RELOAD,	0, reload_chains,
     "Reload chains:\t\treload"},
    {"help",	COMMAND_HELP,	0, printhelp,
     "Get help:\t\thelp"},
    {"dump",	COMMAND_DUMP,	0, dump_state,
     "Dump all info:\t\tdump"},
    {"reset",	COMMAND_RESET,	0, reset,
     "Reset state:\t\treset"},
    {"quit",	COMMAND_QUIT,	0, quit,
     "Quit:\t\t\tquit"},
    {"savestate",COMMAND_SAVESTATE,1, save_state,
     "Save state to file:\tsavestate <file name>"},
    {"loadstate",COMMAND_LOADSTATE,1, load_state,
     "Load state from file:\tloadstate <file name>"},
    {"count",COMMAND_COUNT,0, return_count,
     "Count active entries:\tcount"},
    {"rss",COMMAND_RSS,0, return_rss,
     "Get RSS:\t\trss"},
    {"vsize",COMMAND_VSIZE,0, return_vsize,
     "Get vsize:\t\tvsize"},
    {"memdebug",COMMAND_MEMDEBUG,1, do_memdebug,
     "Mem usage debugging:\tmemdebug {0,1}"},
    {"addblock",COMMAND_ADDBLOCK,2, do_addblock,
     "Add tcp block:\taddblock <address> <list of chains>"},
    {"delblock",COMMAND_DELBLOCK,2, do_delblock,
     "Delete tcp block:\tdelblock <address> <list of chains>"}
  };

#define NCOMMANDS (sizeof(commandtab)/sizeof(struct commandtabnode))

/* Helpers */

/*
  Reset the state to basic, removing all chains and emptying the user list
  */
void do_reset(usernode *users, void *accounting_handle)
{
  syslog(LOG_NOTICE, "Resetting..");
  mymalloc_pushcontext("do_reset()");
  fchain_unloadall();
  mymalloc_popcontext();
  freeUserList(users, accounting_handle);
  mymalloc_popcontext();
  mymalloc_pushcontext("mainloop()");
}

/* Unload and reload all the filter chain rules for all the users. */
int do_reloadchains(usernode users)
{
  namelist tmplist;
  usernode tmpsubj=users;
  mymalloc_pushcontext("do_reloadchains()");
  fchain_unloadall();
  while (tmpsubj)
    {
      /* Each 'user' can be present in several different chains */
      tmplist=tmpsubj->filter_chains; 
      while (tmplist)
	{
	  fchain_addrule(tmpsubj->address, tmplist->name);
	  tmplist=tmplist->next;
	} /* tmplist */
      tmpsubj=tmpsubj->next;
    } /* tmpsubj */
  mymalloc_popcontext();
  mymalloc_popcontext();
  mymalloc_pushcontext("mainloop()");
  return 1;
}

/* Load a complete state from a file. The current state is reset first.
   Some rudimentary sanity checks are done on the data, but we tend
   to trust it. If 'csocket' is not -1, we send replies to the client
   on the other end.
*/
void do_load_state(int csocket, char *filename, usernode *users,
		   struct sockaddr_in *ping_source, void *accounting_handle)
{
  FILE *dumpfile;
  int ok=1;
  static char tmpbuf[BUFSIZE], astring[BUFSIZE], nstring[BUFSIZE],
    sastring[BUFSIZE], chainstring[BUFSIZE];
  namelist chains=NULL, tmplist;
  struct in_addr address, source_address;
  int type, ifindex;
  time_t added;
  mymalloc_pushcontext("do_load_state()");
  /* Silently protect our buffers */
  if (strlen(filename)>(BUFSIZE-200))
    filename[BUFSIZE-200]='\0';
  if ((dumpfile=fopen(filename,"r"))==NULL)
    {
      syslog(LOG_ERR,"loadstate: %s: %m", filename);
      sprintf(tmpbuf,"loadstate: %s: %s", filename, strerror(errno));
      if (csocket!=-1)
	{
	  hlcrypt_Send(csocket, "1", NULL);
	  hlcrypt_Send(csocket, tmpbuf, NULL);
	}
    }
  else /* fopen() */
    {
      while (fgets(tmpbuf, sizeof(tmpbuf), dumpfile))
	{
	  if (tmpbuf[0]!='#')
	    {
	      added=0;
	      if (sscanf(tmpbuf,"%128s\t%128s\t%i\t%128s\t%i\t%li\t%128s\n",
			 astring,nstring,&ifindex,
			 sastring,&type,&added,chainstring) &&
		  inet_aton(astring,&address) &&
		  inet_aton(sastring,&source_address))
		{
		  if (!findUser(*users,&address))
		    {
		      chains=NULL;
		      if (splitstring(chainstring, ',', &chains)>0)
			{
			  if ((ifindex=find_interface(&address,
						       &source_address,
						      tmpbuf, sizeof(tmpbuf)))<0)
			    {
			      freenamelist(&chains);
			      syslog(LOG_ERR,"loadstate: addUser failed");
			      if (csocket!=-1)
				{
				  hlcrypt_Send(csocket, "1", NULL);
				  hlcrypt_Send(csocket, "addUser failed at find_interface()", NULL);
				}
			      ok=0;
			      break;
			    }
			  else
			    {
			      if ((type==USER_TYPE_PING) &&
				  (ping_source->sin_addr.s_addr!=INADDR_ANY))
				memcpy(&(source_address), &(ping_source->sin_addr),
				       sizeof(source_address));
			      
			      if (!addUser(users,nstring,NULL,type,&address,
					      ifindex, tmpbuf, &source_address,chains,
					      added, accounting_handle))
				{
				  freenamelist(&chains);
				  syslog(LOG_ERR,"loadstate: addUser failed");
				  if (csocket!=-1)
				    {
				      hlcrypt_Send(csocket, "1", NULL);
				      hlcrypt_Send(csocket, "addUser failed", NULL);
				    }
				  ok=0;
				  break;
				}
			      else /* addUser() */
				{
				  syslog(LOG_NOTICE, 
					 "Adding %s, %s, type %s, chains %s",
					 inet_ntoa(address),
					 nstring,
					 (type==USER_TYPE_PING)?"ping":"arpping",
					 chainstring);
				  tmplist=chains;
				  while (tmplist)
				    {
				      fchain_addrule(address,tmplist->name);
				      tmplist=tmplist->next;
				    }
				}
			    }
			}
		      else /* splitstring - chains */
			{
			  syslog(LOG_ERR,"loadstate: no chains");
			  if (csocket!=-1)
			    {
			      hlcrypt_Send(csocket, "1", NULL);
			      hlcrypt_Send(csocket, "Syntax error in file", NULL);
			    }
			  ok=0;
			  break;
			}
		    } /* findUser() */
		}
	      else /* sscanf(), inet_aton() x 2 */
		{
		  syslog(LOG_ERR,"loadstate: Syntax error in file");
		  if (csocket!=-1)
		    {
		      hlcrypt_Send(csocket, "1", NULL);
		      hlcrypt_Send(csocket, "Syntax error in file", NULL);
		    }
		  ok=0;
		  break;
		}
	    } /* Otherwise a comment, so ignore */
	} /* while */
      fclose(dumpfile);
      if (ok)
	{
	  syslog(LOG_ERR,"Loaded state from %s", filename);
	  if (csocket!=-1)
	    {
	      hlcrypt_Send(csocket, "1", NULL);
	      hlcrypt_Send(csocket, "OK", NULL);
	    }
	}
    } /* fopen() */
  mymalloc_popcontext();
}

/* Save the current state to a given file, if possible
 */

void do_save_state(int csocket, char *filename, usernode users)
{
  FILE *dumpfile;
  usernode tmpnode=users;
  namelist tmplist;
  static char tmpbuf[BUFSIZE], tmpbuf2[BUFSIZE];

  /* Try to open the file */
  if ((dumpfile=fopen(filename,"w"))==NULL)
    {
      syslog(LOG_ERR,"savestat: %s: %m", filename);
      sprintf(tmpbuf,"savestat: %s: %s", filename, strerror(errno));
      if (csocket!=-1)
	{
	  hlcrypt_Send(csocket, "1", NULL);
	  hlcrypt_Send(csocket, tmpbuf, NULL);
	}
    }
  else /* fopen */
    {
      /* Print a descriptive header */
      fprintf(dumpfile,
	      "# Address\taccount\tIf idx\tSource Addr.\tType\tAdded\tChains\n");
      fprintf(dumpfile,
	      "# -----------------------------------------------------------\n");

      /* Walk the list of user nodes */
      while (tmpnode)
	{
	  /* make a single string from the list of chains */
	  tmplist=tmpnode->filter_chains;
	  tmpbuf[0]='\0';
	  while (tmplist &&
		 ((strlen(tmpbuf)+strlen(tmplist->name)+1)<BUFSIZE))
	    {
	      strcat(tmpbuf, tmplist->name);
	      if (tmplist->next)
		strcat(tmpbuf,",");
	      tmplist=tmplist->next;
	    }

	  /*
	    Convert and save the source address
	    (inet_ntoa uses a static buffer)
	    */
	  strncpy(tmpbuf2,inet_ntoa(tmpnode->source_address),BUFSIZE);
	  tmpbuf2[BUFSIZE-1]='\0';

	  /* ...and print out this user to the file on one line */
	  fprintf(dumpfile,"%s\t%s\t%d\t%s\t%d\t%ld\t%s\n",
		  inet_ntoa(tmpnode->address),
		  tmpnode->account,
		  tmpnode->ifindex,
		  tmpbuf2,
		  tmpnode->user_type,
		  tmpnode->added,
		  tmpbuf
		  );
	  tmpnode=tmpnode->next;
	} /* while */
      fclose(dumpfile);
      if (csocket!=-1)
	{
	  hlcrypt_Send(csocket, "1", NULL);
	  hlcrypt_Send(csocket, "OK", NULL);
	}
      syslog(LOG_NOTICE, "Saved state to %s", filename);
    }
}

/* Send a single status information block to a client, for one specific
   'user'.
   Note: This block must as always be preceded by a string containing the
   total number of lines that are going to be sent. The number of lines
   per 'user' is defined as STAT_LINES below. Multiply it by the number
   of blocks sent and send the result before calling this function.
   Check dump_state() for an example.
   */
#define STAT_LINES 12

void send_single_stat(int csocket, usernode thisnode)
{
  static char tmpbuf[BUFSIZE], tmpbuf2[BUFSIZE];
  namelist tmplist;
  sprintf(tmpbuf,"Address: %.64s", inet_ntoa(thisnode->address));
  hlcrypt_Send(csocket, tmpbuf, NULL);
  sprintf(tmpbuf,"Account: %.64s", thisnode->account);
  hlcrypt_Send(csocket, tmpbuf, NULL);
  sprintf(tmpbuf,"Session id: %.16s", thisnode->session_id);
  hlcrypt_Send(csocket, tmpbuf, NULL);
  sprintf(tmpbuf,"Entry added %.64s", ctime(&(thisnode->added)));
  chop(tmpbuf);
  hlcrypt_Send(csocket, tmpbuf, NULL);
  sprintf(tmpbuf,"Source interface index: %d", thisnode->ifindex);
  hlcrypt_Send(csocket, tmpbuf, NULL);
  sprintf(tmpbuf,"Source interface address: %.64s",
	  inet_ntoa(thisnode->source_address));
  hlcrypt_Send(csocket, tmpbuf, NULL);
  switch (thisnode->user_type)
    {
    case USER_TYPE_PING:
      sprintf(tmpbuf,"Type: ping");
      break;
    case USER_TYPE_ARPPING:
      sprintf(tmpbuf,"Type: arpping");
      if (thisnode->ll_address_set>0)
	{
	  sprintf(tmpbuf2,", %02X:%02X:%02X:%02X:%02X:%02X",
		  thisnode->ll_address.sll_addr[0],
		  thisnode->ll_address.sll_addr[1],
		  thisnode->ll_address.sll_addr[2],
		  thisnode->ll_address.sll_addr[3],
		  thisnode->ll_address.sll_addr[4],
		  thisnode->ll_address.sll_addr[5]);
	  strcat(tmpbuf, tmpbuf2);
	}
      break;
    case USER_TYPE_NONE:
      sprintf(tmpbuf,"Type: (disabled)");
      break;
    default:
      sprintf(tmpbuf,"Type: %d (unknown type)", thisnode->user_type);
      break;
    }
  hlcrypt_Send(csocket, tmpbuf, NULL);
  strcpy(tmpbuf,"Chains: ");
  tmplist=thisnode->filter_chains;
  while (tmplist)
    {
      strcat(tmpbuf, tmplist->name);
      if (tmplist->next)
	strcat(tmpbuf,",");
      tmplist=tmplist->next;
    }
  hlcrypt_Send(csocket, tmpbuf, NULL);
  sprintf(tmpbuf,"Missed replies: %d", thisnode->missed);
  hlcrypt_Send(csocket, tmpbuf, NULL);
  sprintf(tmpbuf,"Received replies (total): %d", thisnode->hits);
  hlcrypt_Send(csocket, tmpbuf, NULL);
  sprintf(tmpbuf,"Last received reply: %.64s", ctime(&(thisnode->last_received)));
  chop(tmpbuf);
  hlcrypt_Send(csocket, tmpbuf, NULL);
  sprintf(tmpbuf,"Last sent packet: %.64s", ctime(&(thisnode->last_sent)));
  chop(tmpbuf);
  hlcrypt_Send(csocket, tmpbuf, NULL);
}

void check_flood(usernode user, struct config *conf)
{
  time_t now;
  if (!strlen(conf->stat_blockchain))
    return;
  time(&now);
  if ((now - user->last_stat) < conf->stat_timelimit)
    {
      user->statmit_count++;
      if ((user->statmit_count >= conf->stat_countlimit) &&
	  (user->block_installed==0))
	{
	  fchain_addrule(user->address, conf->stat_blockchain);
	  user->block_installed=now;
	  user->statmit_count=0;
	}
    }
  else
    {
      if (user->block_installed)
	{
	  fchain_delrule(user->address, conf->stat_blockchain);
	  user->block_installed=0;
	  user->statmit_count=0;
	}
    }
  user->last_stat=now;
}


/********************** COMMAND EXECUTORS ***********************/

/*
  Command: HELP

  Print usage text
  */
void printhelp(int csocket, namelist parms, usernode *users, struct config *conf)
{
  char x[32];
  int i;
  syslog(LOG_NOTICE, "Command: help");
  sprintf(x,"%d",NCOMMANDS+1);
  hlcrypt_Send(csocket, x, NULL);
  hlcrypt_Send(csocket, "Usage:", NULL);
  for (i=0; i<NCOMMANDS; i++)
    hlcrypt_Send(csocket, commandtab[i].usage, NULL);
}

/*
  Command: ADD

  Add a new 'user' node to the list, after validating it, and determining
  the interface index and 'user' type etc.
  This command accepts hostnames or IP adresses.
 */
void add_user(int csocket, namelist parms, usernode *users, struct config *conf)
{
  static char tmpbuf[BUFSIZE], useraddr[BUFSIZE];
  namelist chains=NULL, tmplist;
  struct in_addr user_address, source_address;
  int type, ifindex;
  usernode thisnode;

  syslog(LOG_NOTICE, "Command: add");
  /* Try to extract an IP address from the name/adress received */
  mymalloc_pushcontext("add_user()");
  if (makeaddress(parms->name, &user_address))
    {
      /* Prepare a nice string for logging purposes */
      strncpy(useraddr,inet_ntoa(user_address), BUFSIZE);
      useraddr[BUFSIZE-1]='\0';
      if (strcmp(parms->name,useraddr))
	sprintf(useraddr,"%s/%s",parms->name,inet_ntoa(user_address));

      /* Check if this user is already present */
      if ((thisnode=findUser(*users, &user_address))!=NULL)
	{
	  syslog(LOG_NOTICE, "Add: user %s already active",useraddr);
	  check_flood(thisnode, conf);
	  hlcrypt_Send(csocket,"1", NULL);
	  hlcrypt_Send(csocket,"Already there", NULL);
	}
      else /* findUser */
	{
	  /* Convert the list of chains to a linked list */
	  if (splitstring(parms->next->next->name,',',&chains)>0)
	    {
	      /* Determine the interface index and source address */
	      if ((ifindex=find_interface(&user_address,
					  &source_address,
					  tmpbuf, sizeof(tmpbuf)))>=0)
		{
		  /* Determine the user type */
		  if ((type=determine_type(&user_address, NULL)) != 
		      USER_TYPE_NONE)
		    {
		      if ((type==USER_TYPE_PING) &&
			  (conf->defaultping.ping_source.sin_addr.s_addr!=INADDR_ANY))
			  memcpy(&(source_address), &(conf->defaultping.ping_source.sin_addr),
			       sizeof(source_address));

		      syslog(LOG_NOTICE, 
			     "Adding %s, %s, type %s, chains %s",
			     useraddr,
			     parms->next->name,
			     (type==USER_TYPE_PING)?"ping":"arpping",
			     parms->next->next->name);	
		      /*		      syslog(LOG_NOTICE, "Using %s as source address", inet_ntoa(source_address));*/
		      /* Add the user to the list */
		      if (!addUser(users, parms->next->name, NULL, type,
				      &user_address, ifindex, tmpbuf,
				      &source_address, chains, time(NULL),
				      conf->accounting_handle))
			{
			  freenamelist(&chains);
			  hlcrypt_Send(csocket,"1", NULL);
			  hlcrypt_Send(csocket,"add: failed.", NULL);
			}
		      else /* addUser */
			{
			  hlcrypt_Send(csocket,"1", NULL);
			  hlcrypt_Send(csocket,"OK", NULL);
			  /* Add the IP adress of this user to each of the
			     filter chains requested */
			  tmplist=chains;
			  while (tmplist)
			    {
			      fchain_addrule(user_address,tmplist->name);
			      tmplist=tmplist->next;
			    }
			}
		    }
		  else /* determine_type */
		    {
		      syslog(LOG_NOTICE,
			     "Add: determine_type failed for user %s",
			     useraddr);
		      freenamelist(&chains);
		      hlcrypt_Send(csocket,"1", NULL);
		      hlcrypt_Send(csocket,"add: failed.", NULL);
		    }
		}
	      else /* find_interface */
		{
		  syslog(LOG_NOTICE,
			 "Add: find_interface failed for user %s",
			 useraddr);
		  freenamelist(&chains);
		  hlcrypt_Send(csocket,"1", NULL);
		  hlcrypt_Send(csocket,"add: failed.", NULL);
		}
	    }
	  else /* splitstring */
	    {
	      syslog(LOG_NOTICE, "Add: no chains for user %s",useraddr);
	      hlcrypt_Send(csocket,"1", NULL);
	      hlcrypt_Send(csocket,"add: failed.", NULL);
	    }
	} /* findUser */
    }
  else /* makeaddress */
    {
      syslog(LOG_NOTICE, "Add: user %s unparseable",parms->name);
      hlcrypt_Send(csocket,"1", NULL);
      hlcrypt_Send(csocket,"add: Unknown address" , NULL);
    }
  mymalloc_popcontext();
}


/*
  Command: STAT

  Send info on one specific user.
  This command accepts hostnames or IP adresses.
  */
void send_stat(int csocket, namelist parms, usernode *users, struct config *conf)
{
  static char tmpbuf[BUFSIZE];
  struct in_addr user_address;
  usernode thisnode;
  syslog(LOG_NOTICE, "Command: stat");
  /* Convert the given user reference to an IP address and find the
     user in our list */
  if (makeaddress(parms->name, &user_address) &&
      (thisnode=findUser(*users, &user_address)))
    {
      strncpy(tmpbuf,inet_ntoa(user_address),BUFSIZE);
      tmpbuf[BUFSIZE-1]='\0';
      if (strcmp(parms->name,tmpbuf))
	sprintf(tmpbuf,"%s/%s",parms->name,inet_ntoa(user_address));
      syslog(LOG_NOTICE, "Stat: %s", tmpbuf);
      check_flood(thisnode, conf);
      sprintf(tmpbuf,"%d",STAT_LINES);
      hlcrypt_Send(csocket,tmpbuf, NULL);
      send_single_stat(csocket, thisnode);
    }
  else /* makeaddress */
    {
      syslog(LOG_NOTICE, "Stat: %s unparseable or unknown", parms->name); 
      hlcrypt_Send(csocket,"1", NULL);
      hlcrypt_Send(csocket,"ERROR: Unknown address", NULL);
    }
}

/*
  Command: CHECK

  Check if a user is logged in
  This command accepts hostnames or IP adresses.
  */
void do_check(int csocket, namelist parms, usernode *users, struct config *conf)
{
  static char tmpbuf[BUFSIZE];
  struct in_addr user_address;
  usernode thisnode;
  /*  syslog(LOG_NOTICE, "Command: check");*/
  /* Convert the given user reference to an IP address and find the
     user in our list */
  hlcrypt_Send(csocket,"1", NULL);
  if (makeaddress(parms->name, &user_address) &&
      (thisnode=findUser(*users, &user_address)))
    {
      strncpy(tmpbuf,inet_ntoa(user_address),BUFSIZE);
      tmpbuf[BUFSIZE-1]='\0';
      if (strcmp(parms->name,tmpbuf))
	sprintf(tmpbuf,"%s/%s",parms->name,inet_ntoa(user_address));
      syslog(LOG_NOTICE, "Check: %s found", tmpbuf);
      check_flood(thisnode, conf);
      hlcrypt_Send(csocket,"Yes", NULL);
    }
  else /* makeaddress */
    {
      syslog(LOG_NOTICE, "Check: %s not found", parms->name); 
      hlcrypt_Send(csocket,"No", NULL);
    }
}

/*
  Command: DEL

  Delete a user from our list and remove it from the filter chains.
  This command accepts hostnames or IP adresses.
  */
void del_user(int csocket, namelist parms, usernode *users, struct config *conf)
{
  struct in_addr user_address;
  static char tmpbuf[BUFSIZE], tmpbuf2[BUFSIZE];
  usernode thisuser;
  namelist tmplist;
  time_t elapsed;
  syslog(LOG_NOTICE, "Command: del");
  mymalloc_pushcontext("del_user()");
  /* Convert the given user reference to an IP address */
  if (makeaddress(parms->name, &user_address))
    {
      /* Prepare a nice string for logging purposes */
      strncpy(tmpbuf, inet_ntoa(user_address), BUFSIZE);
      tmpbuf[BUFSIZE-1]='\0';
      if (strcmp(parms->name,tmpbuf))
	sprintf(tmpbuf,"%s/%s",parms->name,inet_ntoa(user_address));

      /* Try to find the user in our list */
      if (!(thisuser=findUser(*users, &user_address)))
	{
	  syslog(LOG_NOTICE, "Del: user %s is unknown",tmpbuf);
	  hlcrypt_Send(csocket,"1", NULL);
	  hlcrypt_Send(csocket,"Not there", NULL);
	}
      else /* findUser */
	{
	  /* Remove all the filter chain rules for this user */
	  tmplist=thisuser->filter_chains;
	  while (tmplist)
	    {
	      fchain_delrule(thisuser->address, tmplist->name);
	      tmplist=tmplist->next;
	    }
	  time(&elapsed);
	  elapsed-=thisuser->added;
	  
	  strcpy(tmpbuf2, ctime(&(thisuser->added)));
	  chop(tmpbuf2);

	  syslog(LOG_NOTICE, "Del: deleting %s, %s after %02d.%02d.%02d. Logged in %s. %u responses received",
		 tmpbuf,
		 thisuser->account,
		 (int)(elapsed/3600),
		 (int)(elapsed%3600)/60,
		 (int)(elapsed%60),
		 tmpbuf2,
		 thisuser->hits
		 );

	  if (strlen(conf->stat_blockchain) && thisuser->block_installed)
	    fchain_delrule(thisuser->address, conf->stat_blockchain);

	  delUser(users,&user_address, conf->accounting_handle);
	  hlcrypt_Send(csocket,"1", NULL);
	  hlcrypt_Send(csocket,"OK", NULL);
	}
    }
  else /* makeadress */
    {
      syslog(LOG_NOTICE, "Del: %s unparseable", parms->name); 
      hlcrypt_Send(csocket,"1", NULL);
      hlcrypt_Send(csocket,"del: Unknown address", NULL);
    }
  mymalloc_popcontext();
}

/*
  Command: RELOAD

  Reload all filter chains.
  */
void reload_chains(int csocket, namelist parms, usernode *users, struct config *conf)
{
  syslog(LOG_NOTICE, "Command: reload");
  hlcrypt_Send(csocket,"1", NULL);
  if (do_reloadchains(*users))
    hlcrypt_Send(csocket,"OK", NULL);
  else
    hlcrypt_Send(csocket,"Failed", NULL);
}

/*
  Command: RESET
  
  Remove all filter chain rules and empty our list of users.
 */
void reset(int csocket, namelist parms, usernode *users, struct config *conf)
{
  syslog(LOG_NOTICE, "Command: reset");
  do_reset(users, conf->accounting_handle);
  hlcrypt_Send(csocket,"1", NULL);
  hlcrypt_Send(csocket,"OK", NULL);
}

/*
  Command: QUIT
  
  Remove all filter chain rules and quit.
 */
void quit(int csocket, namelist parms, usernode *users, struct config *conf)
{
  syslog(LOG_NOTICE, "Command: quit");
  do_reset(users, conf->accounting_handle);
  hlcrypt_Send(csocket,"1", NULL);
  hlcrypt_Send(csocket,"OK", NULL);
  if (conf->accounting_handle)
    acct_cleanup(conf->accounting_handle);
  close(csocket);
  exit(0);
}

/*
  Command: DUMP

  'dump' all the info on all the nodes to the client.
  */
void dump_state(int csocket, namelist parms, usernode *users, struct config *conf)
{
  static char tmpbuf[BUFSIZE];
  int i=0;
  usernode thisnode=*users;
  syslog(LOG_NOTICE, "Command: dump");
  /* Count the users */
  while (thisnode)
    {
      i++;
      thisnode=thisnode->next;
    }

  /* Send the number of strings to the client */
  sprintf(tmpbuf,"%d",(STAT_LINES+1)*i);
  hlcrypt_Send(csocket, tmpbuf, NULL);

  /* ...and then send all the data */
  thisnode=*users;
  while (thisnode)
    {
      hlcrypt_Send(csocket,"----------------------------", NULL);
      send_single_stat(csocket, thisnode);
      thisnode=thisnode->next;
    }
}

/*
  Command: SAVESTATE

  Save all our data to a file that can be loaded later.
  */
void save_state(int csocket, namelist parms, usernode *users, struct config *conf)
{
  syslog(LOG_NOTICE, "Command: savestate");
  do_save_state(csocket, parms->name, *users);
}

/*
  Command: LOADSTATE

  Reset and then load the state from the given file.
  */
void load_state(int csocket, namelist parms, usernode *users, struct config *conf)
{
  syslog(LOG_NOTICE, "Command: loadstate");
  do_reset(users, conf->accounting_handle);
  do_load_state(csocket, parms->name, users, &(conf->defaultping.ping_source), conf->accounting_handle);
}

/*
  Command: COUNT
  
  Count active users
 */
void return_count(int csocket, namelist parms, usernode *users, struct config *conf)
{
  static char tmpbuf[BUFSIZE];
  int count=0;
  usernode tmpnode=*users;
  syslog(LOG_NOTICE, "Command: count");
  while(tmpnode)
    {
      count++;
      tmpnode=tmpnode->next;
    }
  hlcrypt_Send(csocket,"1", NULL);
  sprintf(tmpbuf,"%d",count);
  hlcrypt_Send(csocket,tmpbuf, NULL);
}

/*
  Command: RSS
  
  return RSS
 */
void return_rss(int csocket, namelist parms, usernode *users, struct config *conf)
{
  static char tmpbuf[BUFSIZE];
  syslog(LOG_NOTICE, "Command: rss");
  hlcrypt_Send(csocket,"1", NULL);
  sprintf(tmpbuf,"%d",getRSS());
  hlcrypt_Send(csocket,tmpbuf, NULL);
}

/*
  Command: VSIZE
  
  return VSIZE
 */
void return_vsize(int csocket, namelist parms, usernode *users, struct config *conf)
{
  static char tmpbuf[BUFSIZE];
  syslog(LOG_NOTICE, "Command: vsize");
  hlcrypt_Send(csocket,"1", NULL);
  sprintf(tmpbuf,"%lu",getvsize());
  hlcrypt_Send(csocket,tmpbuf, NULL);
}

/*
  Command: MEMDEBUG

  set/unset malloc() debug flag
  */
void do_memdebug(int csocket, namelist parms, usernode *users, struct config *conf)
{
  int v;
  static char tmpbuf[BUFSIZE];
  sscanf(parms->name,"%i",&v);
  mymalloc_setdebug(v);
  hlcrypt_Send(csocket,"1", NULL);
  sprintf(tmpbuf,"Memory debugging is %s",v?"enabled":"disabled");
  hlcrypt_Send(csocket,tmpbuf, NULL);
}

/*
  Command: ADDBLOCK

  Add a tcp block filter line.
  This command accepts hostnames or IP adresses.
 */
void do_addblock(int csocket, namelist parms, usernode *users, struct config *conf)
{
  static char tmpbuf[BUFSIZE];
  namelist chains=NULL, tmplist;
  struct in_addr user_address;
  syslog(LOG_NOTICE, "Command: addblock");
  /* Try to extract an IP address from the name/adress received */
  mymalloc_pushcontext("do_addblock()");
  if (makeaddress(parms->name, &user_address))
    {
      /* Prepare a nice string for logging purposes */
      strncpy(tmpbuf,inet_ntoa(user_address), BUFSIZE);
      tmpbuf[BUFSIZE-1]='\0';
      if (strcmp(parms->name,tmpbuf))
	sprintf(tmpbuf,"%s/%s",parms->name,inet_ntoa(user_address));

	  /* Convert the list of chains to a linked list */
	  if (splitstring(parms->next->name,',',&chains)>0)
	    {
	      /* Add the IP adress of this user to each of the
		 filter chains requested */
	      tmplist=chains;
	      while (tmplist)
		{
		  fchain_addrule(user_address,tmplist->name);
		  tmplist=tmplist->next;
		}
	      hlcrypt_Send(csocket,"1", NULL);
	      hlcrypt_Send(csocket,"OK", NULL);
	    }
	  else /* splitstring */
	    {
	      syslog(LOG_NOTICE, "Addblock: no chains specified for user %s",tmpbuf);
	      hlcrypt_Send(csocket,"1", NULL);
	      hlcrypt_Send(csocket,"addblock: failed.", NULL);
	    }
    }
  else /* makeaddress */
    {
      syslog(LOG_NOTICE, "Addblock: user %s unparseable",parms->name);
      hlcrypt_Send(csocket,"1", NULL);
      hlcrypt_Send(csocket,"addblock: Unknown address", NULL);
    }
  mymalloc_popcontext();
}

/*
  Command: DELBLOCK

  Remove a tcp block filter line.
  This command accepts hostnames or IP adresses.
 */
void do_delblock(int csocket, namelist parms, usernode *users, struct config *conf)
{
  static char tmpbuf[BUFSIZE];
  namelist chains=NULL, tmplist;
  struct in_addr user_address;
  syslog(LOG_NOTICE, "Command: delblock");
  /* Try to extract an IP address from the name/adress received */
  mymalloc_pushcontext("do_delblock()");
  if (makeaddress(parms->name, &user_address))
    {
      /* Prepare a nice string for logging purposes */
      strncpy(tmpbuf,inet_ntoa(user_address), BUFSIZE);
      tmpbuf[BUFSIZE-1]='\0';
      if (strcmp(parms->name,tmpbuf))
	sprintf(tmpbuf,"%s/%s",parms->name,inet_ntoa(user_address));

	  /* Convert the list of chains to a linked list */
	  if (splitstring(parms->next->name,',',&chains)>0)
	    {
	      /* Add the IP adress of this user to each of the
		 filter chains requested */
	      tmplist=chains;
	      while (tmplist)
		{
		  fchain_delrule(user_address,tmplist->name);
		  tmplist=tmplist->next;
		}
	      hlcrypt_Send(csocket,"1", NULL);
	      hlcrypt_Send(csocket,"OK", NULL);
	    }
	  else /* splitstring */
	    {
	      syslog(LOG_NOTICE, "Delblock: no chains specified for user %s",tmpbuf);
	      hlcrypt_Send(csocket,"1", NULL);
	      hlcrypt_Send(csocket,"delblock: failed.", NULL);
	    }
    }
  else /* makeaddress */
    {
      syslog(LOG_NOTICE, "Delblock: user %s unparseable",parms->name);
      hlcrypt_Send(csocket,"1", NULL);
      hlcrypt_Send(csocket,"delblock: Unknown address", NULL);
    }
  mymalloc_popcontext();
}

/****************************************************************************/

/*
  Note: response will contain a 'usage' string if the parameter count is
  incorrect.
  Permissions are checked against the "perms" attribute for this client in
  the configuration file. If the attribute is missing or if it contains "any",
  the command is accepted. Otherwise, the command must be present in the
  comma-separated list of commands in "perms".
 */
int check_command(char *cmd, char *clientname, char *conffile,
		  namelist *parms, char *command, int size_command, char **response,
		  command_handler *fcall)
{
  int args, i;
  namelist tmplist;
  static char tmpbuf[BUFSIZE];
  int ret=COMMAND_UNKNOWN;
  if ((args=splitstring(cmd,' ', parms))<=0)
    return COMMAND_UNKNOWN;
  /* Skip the command itself and count only parameters */
  args--;

  /* Copy the command name from the head of the list and drop it */
  strncpy(command, (*parms)->name, size_command);
  command[size_command-1]='\0';
  tmplist=(*parms);
  (*parms)=(*parms)->next;
  tmplist->next=NULL;
  freenamelist(&tmplist);
  (*response)=NULL;
  for (i=0; i<NCOMMANDS; i++)
    {
      if (!strcasecmp(command, commandtab[i].name))
	{
	  if (args==commandtab[i].args)
	    {
	      (*fcall)=commandtab[i].fcall;
	      ret=commandtab[i].token;
	    }
	  else
	    {
	      (*response)=commandtab[i].usage;
	      freenamelist(parms);
	      return COMMAND_ARGS;
	    }
	}
    }
  /* If command is known and the number of arguments correct,
     check permissions */
  if ((ret!=COMMAND_UNKNOWN) &&
      conf_getvar(conffile, "client", clientname, "perms", tmpbuf,
		  sizeof(tmpbuf)))
    {
      tmplist=NULL;
      if (!splitstring(tmpbuf,',',&tmplist) ||
	  !(findname(tmplist, "any") ||
	    findname(tmplist, command)))
	{
	  freenamelist(&tmplist);
	  freenamelist(parms);
	  return COMMAND_PERMS;
	}
      else
	freenamelist(&tmplist);
    }
    
  return ret;
}

/*
  Parse a command and reply. Always send the number of strings in
  response first
  */

void docommand(struct config *conf,
	       int csocket,
	       char *clientname,
	       usernode *users)
{
  static char tmpbuf[BUFSIZE], command[BUFSIZE];
  static unsigned long oldvsize=0, newvsize;
  namelist parms=NULL;
  char *response=NULL;
  command_handler fcall;
  if (hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, NULL)>0)
    {
      switch (check_command(tmpbuf, clientname, conf->conffile, &parms, command, sizeof(command), &response, &fcall))
	{
	case COMMAND_ARGS:
	  if (!response)
	    response="Failed";
	  hlcrypt_Send(csocket,"1", NULL);
	  hlcrypt_Send(csocket,response, NULL);
	  dejunkifyforlog(tmpbuf);
	  syslog(LOG_ERR,
		 "Parameter error in command \"%s\" from %s",
		 tmpbuf,clientname);
	  break;

	case COMMAND_PERMS:
	  hlcrypt_Send(csocket,"1", NULL);
	  hlcrypt_Send(csocket,"Permission denied", NULL);
	  dejunkifyforlog(tmpbuf);
	  syslog(LOG_ERR,
		 "Permission denied for \"%s\" from %s",tmpbuf,clientname);
	  break;

	case COMMAND_UNKNOWN:
	  dejunkifyforlog(tmpbuf);
	  syslog(LOG_ERR, "Unrecognized command \"%s\" from %s",
		 tmpbuf,clientname);
	  hlcrypt_Send(csocket, "0", NULL);
	  break;
	default:
	  fcall(csocket, parms, users, conf);
	  break;
	}
      if ((newvsize=getvsize())!=oldvsize)
	{
	  syslog(LOG_DEBUG,"VSize changed by %ld bytes during %s", (signed long)newvsize-oldvsize, command);
	  oldvsize=newvsize;
	}
      freenamelist(&parms);
    }
  return;
}


