#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <iptables.h>
#include <string.h>
#include <varlist.h>
#include "filterchains2.h"

iptc_handle_t handle=NULL;
namelist used_chains=NULL;

/* Add a rule to a named chain. Create the chain if it
   doesn't exist, and remember that it is our own chain */
int fchain_addrule(struct in_addr address, char *chain)
{
  char *table = "filter", *actchain=chain;
  int ret;
  namelist tmplist=NULL, tmplist2=used_chains;

  struct in_addr twofiftyfive, zero;
  inet_aton("255.255.255.255", &twofiftyfive);
  inet_aton("0.0.0.0", &zero);

  if (splitstring(chain, ':', &tmplist)==2)
    {
      table=tmplist->name;
      actchain=tmplist->next->name;
    }

  while (tmplist2 && (strcmp(tmplist2->name, chain)))
    tmplist2 = tmplist2->next;
  if (!tmplist2)
    {
      fprintf(stderr,"Creating %s\n",chain);
      if ((ret=iptables_create_chain(table,actchain))==0)
	perror("iptables_create_chain()");
      addname(&used_chains, chain);
    }

  ret=iptables_add_line(table, actchain, &address, &twofiftyfive, &zero, &zero, "ACCEPT");

  freenamelist(&tmplist);
  return ret;
}

/* Remove a given rule from a named chain if it exists */
int fchain_delrule(struct in_addr address, char *chain)
{
  char *table = "filter", *actchain=chain;
  int ret;
  namelist tmplist=NULL;

  struct in_addr twofiftyfive, zero;
  inet_aton("255.255.255.255", &twofiftyfive);
  inet_aton("0.0.0.0", &zero);

  if (splitstring(chain, ':', &tmplist)==2)
    {
      table=tmplist->name;
      actchain=tmplist->next->name;
    }

  ret=iptables_delete_line(table, actchain, &address, &twofiftyfive, &zero, &zero, "ACCEPT");

  freenamelist(&tmplist);
  return ret;
}

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

void checkmem(char *str, int runs)
{
  static int memsize=0, newmemsize;
  static FILE *statfile=NULL;
  static char buf[4096];
  static int pid=0;
  if (!pid)
    pid=getpid();
  if (!statfile)
    {
      sprintf(buf,"/proc/%d/status",pid);
      statfile=fopen(buf,"r");
    }
  fseek(statfile,0,SEEK_SET);
  while (fgets(buf,sizeof(buf),statfile) &&
	 strncmp(buf,"VmRSS",5));
  sscanf(buf,"VmRSS:  %i kB",&newmemsize);
  if (newmemsize!=memsize)
    {
      printf("RSS changed to %d after %s in %d runs\n",newmemsize,str,runs);
      fflush(stdout);
      memsize=newmemsize;
    }
  fclose(statfile);
  statfile=NULL;
}

int main()
{
  char *addresses_txt[]={"192.168.0.1","192.168.0.2","192.168.0.3"};
  struct in_addr *addresses=NULL;
  int acount=sizeof(addresses_txt)/sizeof(char *);
  int i, runs=0, ret;

  addresses=(struct in_addr *)malloc(acount * sizeof(struct in_addr *));
  for (i=0;i<acount;i++)
    inet_aton(addresses_txt[i],&(addresses[i]));

  while (1)
    {
      for (i=0;i<acount;i++)
	if ((ret=fchain_addrule(addresses[i],"foobar"))==0)
	  perror("fchain_addrule()");
      checkmem("add", runs);
      /*      for (i=0;i<acount;i++)
	if ((ret=fchain_delrule(addresses[i],"foobar"))==0)
	  perror("fchain_delrule()");
      checkmem("del", ++runs);*/
      fchain_flush("foobar");
      checkmem("flush", ++runs);
    }
  return 0;
}
