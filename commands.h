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
void do_load_state(int csocket, char *filename, usernode *users,
		   struct sockaddr_in *ping_source, void *accounting_handle);

/*
  Save current state data to the file 'filename' (in), if possible.
  If 'csocket' (in) is not -1, send out a reply on the socket.

  Prerequisites (apart from the obvious):
  * syslog() is used so openlog() before calling this
  */
void do_save_state(int csocket, char *filename, usernode users);

/*
  Receive a command on the socket 'csocket' (in) for an (already authenticated)
  client. Check command, arglist and permissions (using 'conffile' (in)
  and 'clientname' (in)) and execute the command (using 'users' (in).

  Prerequisites (apart from the obvious):
  * syslog() is used so openlog() before calling this
  */
void docommand(struct config *conf, int csocket, char *clientname, usernode *users);

/*
  Reset to basic state, removing all filter chain rules and
  all user nodes in 'users' (in/out).
  */
void do_reset(usernode *users);
