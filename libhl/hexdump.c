#include <stdio.h>

#include "config.h"
#include "divlib.h"

int printable(unsigned char c)
{
  return ((c>=32) && (c!=127));
}

void hexdump(FILE *fd, char *buf, int n)
{
  int i,j,m;
  j=0;
  m=n + 16 - (n % 16);
  for (i=0; i<m; i++)
    {
      if (!(i%16))
	{
	  if (i>0)
	    {
	      fprintf(fd,"  ");
	      for (; j < i ; j++)
		{
		  if (j<n)
		    {
		      if (printable(buf[j]))
			fputc(buf[j],fd);
		      else
			fputc('.',fd);
		    }
		  else
		    fputc(' ',fd);
		}
	      fputc('\n',fd);
	    }
	  fprintf(fd,"%04X: ",i);
	}
      if (i<n)
	fprintf(fd," %02X",buf[i]);
      else
	fprintf(fd,"   ");
    }
  fprintf(fd,"  ");
  for (; j < i ; j++)
    {
      if (j<n)
	{
	  if (printable(buf[j]))
	    fputc(buf[j],fd);
	  else
	    fputc('.',fd);
	}
      else
	fputc(' ',fd);
    }
  fputc('\n',fd);
  fflush(stdout);
}

