#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iplogin2.h>
#include <syslog.h>

#include "stringfunc.h"
#include "conffile.h"

#define BUFSIZE 8192

int main(int argc, char *argv[])
{
  namelist lines=NULL, tmplist;
  static char command[BUFSIZE];
  static char address[BUFSIZE];
  static char account[BUFSIZE];
  static char chains[BUFSIZE];
  char *conffile=CONFFILE;
  char *clientname=NULL;
  varlist junk_vars=NULL;
  static char tmpbuf[BUFSIZE], clientname_buf[BUFSIZE];
  int syslog_facility=LOG_USER, i;

  int ok;
  if (argc!=1 && argc!=2)
    {
      fprintf(stderr,"Usage: %s [clientname]\n",argv[0]);
      return 1;
    }
#ifdef CLIENTNAME
  clientname=CLIENTNAME;
#else
  if (!conf_init(conffile))
    {
      fprintf(stderr,"conf_init(%s) failed\n",conffile);
      return -1;
    }
  conf_rewind();
  if (!conf_next("client", clientname_buf, sizeof(clientname_buf), &junk_vars))
    {
      fprintf(stderr,"No clients found in %s\n",conffile);
      return -1;
    }
  freevarlist(&junk_vars);
  conf_cleanup();
  clientname=clientname_buf;
#endif
  if (argc==2)
    {
      if (!conf_getvar(conffile, "client", argv[1], "key", tmpbuf, sizeof(tmpbuf)))
	{
	  fprintf(stderr, "Client %s in %s is not defined or has no key\n", argv[1], conffile);
	  return -2;
	}
      clientname=argv[1];
    }
  fprintf(stderr, "[Using client %s in %s]\n", clientname, conffile);

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

  openlog(tmpbuf, LOG_PID, syslog_facility);

  while (1)
    {
      ok=0;
      printf("----------------------------------\n");
      printf("Select a function to test:\n\n");
      printf("1) Add a new user\n");
      printf("2) Delete a user\n");
      printf("3) Show status for a user\n");
      printf("4) Any command (try 'help')\n");
      printf("5) Repeat status for a user - break with CTRL-C\n");
      printf("q) Quit this program\n");
      printf("\nYour selection: ");
      fflush(stdout);
      if (!fgets(command,sizeof(command),stdin))
	break;
      else
	{
	  cleanupstring(command);
	  switch(command[0])
	    {
	      /************** LOGIN **************/
	    case '1':
	      printf("Enter address: ");
	      fflush(stdout);
	      if (!fgets(address,sizeof(address),stdin))
		break;
	      printf("Enter account name: ");
	      fflush(stdout);
	      if (!fgets(account,sizeof(account),stdin))
		break;
	      printf("Enter a comma-separated list of filter chains: ");
	      fflush(stdout);
	      if (!fgets(chains,sizeof(chains),stdin))
		break;
	      cleanupstring(address);
	      cleanupstring(account);
	      cleanupstring(chains);
	      /* Remove spaces in the list of chains */
	      if (!splitstring(chains, ',', &lines))
		{
		  printf("Syntax error in chain list\n");
		  ok=1;
		  break;
		}
	      sprintf(chains,lines->name);
	      tmplist=lines->next;
	      while (tmplist)
		{
		  strcat(chains, ",");
		  strcat(chains, tmplist->name);
		  tmplist=tmplist->next;
		}
	      freenamelist(&lines);
	      if (strlen(address) && strlen(account) && strlen(chains))
		{
		  /******* LOOKY HERE ********/
		  if (iplogin2_login(conffile, clientname,
			    address, account, chains))
		    printf("OK\n");
		  else
		    printf("Failed\n");
		}
	      else
		printf("Error in input\n");
	      ok=1;
	      break;

	      /************** LOGOUT **************/
	    case '2':
	      printf("Enter address: ");
	      fflush(stdout);
	      if (!fgets(address,sizeof(address),stdin))
		break;
	      cleanupstring(address);
	      if (strlen(address))
		{
		  /******* LOOKY HERE ********/
		  if (iplogin2_logout(conffile, clientname,
			     address))
		    printf("OK\n");
		  else
		    printf("Failed\n");
		}
	      else
		printf("Error in input\n");
	      ok=1;
	      break;

	      /************** STAT **************/
	    case '3':
	      printf("Enter address: ");
	      fflush(stdout);
	      if (!fgets(address,sizeof(address),stdin))
		break;
	      cleanupstring(address);
	      if (strlen(address))
		{
		  /******* LOOKY HERE ********/
		  if (iplogin2_stat(conffile, clientname,
			      address, &lines))
		    {
		      printf("************** Status for %s ***********\n",
			     address);
		      tmplist=lines;
		      while(tmplist)
			{
			  printf("%s\n",tmplist->name);
			  tmplist=tmplist->next;
			}
		      printf("****************************************\n");
		      freenamelist(&lines);
		    }
		  else
		    printf("Failed\n");
		}
	      else
		printf("Error in input\n");
	      ok=1;
	      break;

	      /************** COMMAND **************/
	    case '4':
	      printf("Enter command: ");
	      fflush(stdout);
	      if (!fgets(command,sizeof(command),stdin))
		break;
	      cleanupstring(command);
	      if (!iplogin2_docommand(conffile, clientname,
			      command, &lines))
		{
		  printf("Failed\n");
		  ok=1;
		  break;
		}
	      else
		{
		  printf("************** Response to \"%s\" ***********\n",
			 command);
		  tmplist=lines;
		  while(tmplist)
		    {
		      printf("%s\n",tmplist->name);
		      tmplist=tmplist->next;
		    }
		  printf("****************************************\n");
		  freenamelist(&lines);
		}
	      ok=1;
	      break;

	      /************** STAT **************/
	    case '5':
	      printf("Enter address: ");
	      fflush(stdout);
	      if (!fgets(address,sizeof(address),stdin))
		break;
	      cleanupstring(address);
	      if (strlen(address))
		{
		  while (1)
		    {
		      printf("%c[2J%c[H",27,27);
		      /******* LOOKY HERE ********/
		      if (iplogin2_stat(conffile, clientname,
				  address, &lines))
			{
			  printf("************** Status for %s ***********\n",
				 address);
			  tmplist=lines;
			  while(tmplist)
			    {
			      printf("%s\n",tmplist->name);
			      tmplist=tmplist->next;
			    }
			  printf("****************************************\n");
			  freenamelist(&lines);
			}
		      else
			printf("Failed\n");
		      sleep(1);
		    }
		}
	      else
		printf("Error in input\n");
	      ok=1;
	      break;

	    case 'q':
	      break;
	      
	    default:
	      ok=1;
	      break;
	    }
	  if (!ok)
	    break;
	}
    }
  
  return 0;
}
