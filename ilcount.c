#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iplogin2.h>


#define BUFSIZE 8192

int main(int argc, char *argv[])
{
  namelist lines=NULL, tmplist;
  char *conffile;
  char *clientname;
  if (argc!=3)
    {
      fprintf(stderr,"Usage: %s <conffile> <clientname>\n",argv[0]);
      return 1;
    }
  
  conffile = argv[1];
  clientname = argv[2];

  if (!iplogin2_docommand(conffile, clientname,
		  "count", &lines)) {
    printf("-1");
  }
  else
    {
      tmplist=lines;
      while(tmplist) {
	printf("%s\n",tmplist->name);
	tmplist=tmplist->next;
      }
      freenamelist(&lines);
    }  
  return 0;
}
