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

/*
  NOTE: All the functions in here will openlog() with the parameters
  found in the configuration file and log to the given facility with the
  given program name. It is probably a good idea to make sure any other
  call to openlog() uses the same parameters..

  This is a potentially unwanted side effect, but it enables the
  initialize() function to get the facility name etc from the configuration
  file instead of having to hardcode the information.

  If the sequence of actions always begins with a call to iplogin2_check(),
  you obviously do not need to openlog() afterwards.
  */

#include "varlist.h"

/*
  Log in a new user.

  'conffile' is the name of the configuration file.
  'clientname' is the name of the client entry to use
  'address' is the IP address of the user
  'account' is the account name of the user
  'chains' is a comma-separated list of filter chains (no whitespace!)

  The server name, client and server key etc are read from the
  configuration file.

  Returns 0 if it fails, !=0 otherwise.
  */
int iplogin2_login(char *conffile, char *clientname,
	  char *address, char *account, char *chains);

/*
  Log out a user.

  'conffile' is the name of the configuration file.
  'clientname' is the name of the client entry to use
  'address' is the IP address of the user

  The server name, client and server key etc are read from the
  configuration file.

  Returns 0 if it fails, !=0 otherwise.
  */
int iplogin2_logout(char *conffile, char *clientname,
	   char *address);

/*
  Log out a user.

  'conffile' is the name of the configuration file.
  'clientname' is the name of the client entry to use
  'username' is the username

  The server name, client and server key etc are read from the
  configuration file.
  
  Returns 0 if it fails, !=0 otherwise.
  */
int iplogin2_logoutuser(char *conffile, char *clientname,
			char *username);

/*
  Check if a host is logged in.

  'conffile' is the name of the configuration file.
  'clientname' is the name of the client entry to use
  'address' is the IP address of the host

  The server name, client and server key etc are read from the
  configuration file.

  Returns 1 if the user is logged in, 0 otherwise.
  */
int iplogin2_check(char *conffile, char *clientname, char *address);

/*
  Check if a user is logged in.

  'conffile' is the name of the configuration file.
  'clientname' is the name of the client entry to use
  'username' is the username

  The server name, client and server key etc are read from the
  configuration file.

  Returns 1 if the user is logged in, 0 otherwise.
  */
int iplogin2_checkuser(char *conffile, char *clientname, char *username);

/*
  Get info about a user.

  'conffile' is the name of the configuration file.
  'clientname' is the name of the client entry to use
  'address' is the IP address of the user

  'lines' is an initialized "namelist" which is filled with
  various info about the user.

  The server name, client and server key etc are read from the
  configuration file.

  De-allocation of 'lines' after use is the responsibility of the
  caller.

  Returns 0 if it fails, !=0 otherwise.
  */
int iplogin2_stat(char *conffile, char *clientname,
	    char *address, namelist *lines);

/*
  Execute any command.

  'conffile' is the name of the configuration file.
  'clientname' is the name of the client entry to use
  'command' is the IP address of the user

  'lines' is an initialized "namelist" which is filled with
  the responses from the server.

  The server name, client and server key etc are read from the
  configuration file.

  De-allocation of 'lines' after use is the responsibility of the
  caller.

  Returns 0 if it fails, !=0 otherwise.
  */
int iplogin2_docommand(char *conffile, char *clientname,
	       char *command, namelist *lines);

#define USER_TYPE_NONE 0
#define USER_TYPE_ARPPING 1
#define USER_TYPE_PING 2

#ifndef SYSLOG_NAMES_H
#define SYSLOG_NAMES_H

typedef struct _syslog_code {
        char    *c_name;
        int     c_val;
} SYSLOG_CODE;

extern SYSLOG_CODE prioritynames[];
extern SYSLOG_CODE facilitynames[];

#endif
