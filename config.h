#ifndef CONFIG_H
#define CONFIG_H

#include <netinet/in.h>

#define CONFBSIZE 8192

/* Configuration parameter block

  'conffile' : The server's configuration file
  'progname' : Used for tcp_wrappers as id in /etc/hosts.allow
  'servername' : Used to find the server key in the conf file
  'accept_interval' : Tuning: interval between each select() call (before accept())
  'accept_timeout' : Tuning: timeout for the select() call before accept()
  'logout_timeout' : Requested timeout in seconds - before deleting an unreachable user
  'pinginterval' : Microseconds between pings
  'min_pinginterval' : Min ping interval in microseconds
  'missdiff' : Tuning: Difference in secs between last sent and last
  received, before we count a miss. Necessary for handling lost packets.
  'maxmissed' : Number of missed packets before killing a user.
  'ping_source' : Source address for pings
  'listen_address' : Address/port to listen on for command connections
  'loadfile' : File name from which to load start state, or NULL.
  'pidfile' : PID file (!)
  */

struct config
{
  char conffile[CONFBSIZE];
  char progname[CONFBSIZE];
  char servername[CONFBSIZE];
  int accept_interval;
  int accept_timeout;
  int logout_timeout;
  unsigned int pinginterval;
  unsigned int min_pinginterval;
  int missdiff;
  int maxmissed;
  struct sockaddr_in ping_source;
  struct sockaddr_in listen_address;
  char loadfile[CONFBSIZE];
  char pidfile[CONFBSIZE];
  void *accounting_handle;
};

char *params(struct config *conf);

#define STAT_TIMELIMIT 60
#define STAT_COUNTLIMIT 3
#define STAT_BLOCKCHAIN "block"
#define STAT_BLOCKTIME 900
#define STAT_BLOCKGC 3600

#endif
