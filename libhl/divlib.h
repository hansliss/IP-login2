#ifndef LIBDIV_H
#define LIBDIV_H

#include <arpa/inet.h>
#include <stdio.h>

void hexdump(FILE *fd, unsigned char *buf, int n);

/* Translate a dotted quad or a hostname to an IP address if
   possible. Return 0 if it fails, non-0 otherwise */
int makeaddress(char *name_or_ip, struct in_addr *res);

/* Translate a service name or port number (as a string) into an NBO
   integer. Return 0 on failure. */
int makeport(char *name_or_port);

/* Remove junk characters from a string for logging and stuff */
void dejunkifyforlog(char *s);

/*
  Remove all blanks at the beginning and end of the string 'string' (in/out).
  */
void cleanupstring(char *string);

/*
  Chop off all whitespace characters (including newline characters etc)
  from the end of the string 'string' (in/out).
  */
void chop(char *string);

#endif
