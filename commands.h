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

#include "usernode.h"
#include "config.h"
/*
  Load state data from the file 'filename' (in) and fill 'users' (in/out)
  with new data, after resetting the current state.
  If 'csocket' (in) is not -1, send out a reply on the socket.

  Returns 0 if not OK, or !=0 otherwise.

  Prerequisites (apart from the obvious):
  * syslog() is used so openlog() before calling this
  */
void do_load_state(int csocket, struct config *conf, char *filename, struct trie *users,
		   struct sockaddr_in *ping_source, void *accounting_handle, HLCRYPT_HANDLE h);

/*
  Save current state data to the file 'filename' (in), if possible.
  If 'csocket' (in) is not -1, send out a reply on the socket.

  Prerequisites (apart from the obvious):
  * syslog() is used so openlog() before calling this
  */
void do_save_state(int csocket, char *filename, struct trie *users, HLCRYPT_HANDLE h);

/*
  Receive a command on the socket 'csocket' (in) for an (already authenticated)
  client. Check command, arglist and permissions (using 'conffile' (in)
  and 'clientname' (in)) and execute the command (using 'users' (in).

  Prerequisites (apart from the obvious):
  * syslog() is used so openlog() before calling this
  */
void docommand(struct config *conf, int csocket, char *clientname, struct trie *users, HLCRYPT_HANDLE h);

/*
  Reset to basic state, removing all filter chain rules and
  all user nodes in 'users' (in/out).
  */
void do_reset(struct trie *users);
