#ifndef CONFIG_H
#define CONFIG_H

#include "autoconfig.h"
#include <netinet/in.h>

#define CONFBSIZE 8192

struct network
{
  struct network *next;
  unsigned int network;
  unsigned int netmask;
};

/* Ping configuration parameters for one interface
  'pinginterval' : Microseconds between pings
  'min_pinginterval' : Min ping interval in microseconds
  'missdiff' : Tuning: Difference in secs between last sent and last
     received, before we count a miss. Necessary for handling lost packets.
  'maxmissed' : Number of missed packets before killing a user.
  'ping_source' : Source address for pings
  */

struct pingconfig
{
  unsigned int pinginterval;
  unsigned int min_pinginterval;
  int missdiff;
  int maxmissed;
  struct sockaddr_in ping_source;
};

/* Configuration parameter block

  'conffile' : The server's configuration file
  'progname' : Used for tcp_wrappers as id in /etc/hosts.allow
  'servername' : Used to find the server key in the conf file
  'accept_interval' : Tuning: interval between each select() call (before accept())
  'accept_timeout' : Tuning: timeout for the select() call before accept()
  'logout_timeout' : Requested timeout in seconds - before deleting an unreachable user
  'listen_address' : Address/port to listen on for command connections
  'loadfile' : File name from which to load start state, or NULL.
  'pidfile' : PID file (!)
  'accounting_handle' : A handle for an accounting library, if present
  'defaultping' : Default ping configuration, as opposed to per-interface config
  'stat_timelimit' : Max time for counting multiple 'stat' commands as bursts when blocking is active
  'stat_countlimit' : Number of 'stat' commands before user is blocked
  'stat_blockchain' : Chain specification for the blocking mechanism
  'stat_blocktime' : Number of seconds user is held in the block chain
  'stat_blockgc' : Number of seconds between automatic cleanups of the block chain
  'counterchain' : Chain to consult for retrieving TX and RX counters
  */

struct config
{
  char conffile[CONFBSIZE];
  char progname[CONFBSIZE];
  char servername[CONFBSIZE];
  int accept_interval;
  int accept_timeout;
  int logout_timeout;
  struct sockaddr_in listen_address;
  char loadfile[CONFBSIZE];
  char pidfile[CONFBSIZE];
  void *accounting_handle;
  struct pingconfig defaultping;
  int stat_timelimit;  /* 60 */
  int stat_countlimit; /* 3 */
  char stat_blockchain[CONFBSIZE]; /* "block/b>DROP" */
  int stat_blocktime; /*  900 */
  int stat_blockgc; /* 3600 */
  char counterchain[CONFBSIZE]; /* For example "users" */
  unsigned int rxidle, txidle;
  struct network *idlenetworks;
  unsigned int counter_interval;
};

char *params(struct config *conf);

#ifndef USER_TYPE_NONE
#define USER_TYPE_NONE 0
#define USER_TYPE_ARPPING 1
#define USER_TYPE_PING 2
#endif
#endif
