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

#include <stdio.h>

#define MIN_PING_INTERVAL 1000
#define DEFAULT_MISSED 5
#define MIN_MISSED 2

#define BUFSIZE 8192

/* Remove all blanks at the beginning and end of a string */

void cleanupstring(char *string)
{
  int i=strlen(string)-1;
  while (i>0 && isspace(string[i]))
    i--;
  string[i+1]='\0';
  i=0;
  while (isspace(string[i]))
    i++;
  memmove(string,&(string[i]),strlen(&(string[i]))+1);
}

int main(int argc, char *argv[])
{
  char tmpbuf[BUFSIZE];
  int number_of_users;
  int ping_interval, min_ping_interval;
  int missed_limit;
  int logout_timeout;
  int margin;
  printf("Enter number of users: ");
  fgets(tmpbuf, BUFSIZE, stdin);
  cleanupstring(tmpbuf);
  sscanf(tmpbuf, "%i", &number_of_users);
  printf("Enter requested logout timeout: ");
  fgets(tmpbuf, BUFSIZE, stdin);
  cleanupstring(tmpbuf);
  sscanf(tmpbuf, "%i", &logout_timeout);
  printf("Enter min ping interval [%d 탎]: ", MIN_PING_INTERVAL);
  fgets(tmpbuf, BUFSIZE, stdin);
  cleanupstring(tmpbuf);
  if (strlen(tmpbuf))
    sscanf(tmpbuf, "%i", &min_ping_interval);
  else
    min_ping_interval=MIN_PING_INTERVAL;
  for (missed_limit=MIN_MISSED; missed_limit<(DEFAULT_MISSED*2); missed_limit++)
    {
      ping_interval=(1000000 * logout_timeout)/(number_of_users * missed_limit);
      if (ping_interval>=min_ping_interval)
	{
	  margin=1000000 * logout_timeout / missed_limit - number_of_users * min_ping_interval;
	  printf("----------------------------------\n");
	  printf("\tMissed replies limit: %d\n", missed_limit);
	  printf("\tLogout timeout (s): %d\n", logout_timeout);
	  printf("\tPing interval (탎): %d\n", ping_interval);
	  printf("\tMargin - free time / cycle (탎) for ping interval=%d 탎: %d\n", min_ping_interval, margin);
	}
    }
  missed_limit=DEFAULT_MISSED;
  ping_interval=(1000000 * logout_timeout)/(number_of_users * missed_limit);
  if (ping_interval<min_ping_interval)
    {
      printf("Adjusting ping interval (%d < %d)\n", ping_interval, min_ping_interval);
      ping_interval=min_ping_interval;
      missed_limit=(1000000 * logout_timeout)/(number_of_users * ping_interval);
      if (missed_limit<MIN_MISSED)
	{
	  printf("Adjusting missed packets limit (%d < %d)\n", missed_limit, MIN_MISSED);
	  missed_limit=MIN_MISSED;
	  logout_timeout=number_of_users * missed_limit * ping_interval / 1000000;
	}
    }
  margin=1000000 * logout_timeout / missed_limit - number_of_users * min_ping_interval;
  printf("----------------------------------\n");
  printf("Number of users: %d\n", number_of_users);
  printf("Logout timeout (s): %d\n", logout_timeout);
  printf("Missed replies limit: %d\n", missed_limit);
  printf("Ping interval (탎): %d\n", ping_interval);
  printf("Margin - free time / cycle (탎) for ping interval=%d 탎: %d\n", min_ping_interval, margin);

  return 0;
}
