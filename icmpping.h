#include <linux/sockios.h>

/*
  Send an ICMP 'echo request' packet to the address of 'user' (in).
  'rawsockets' (in/out) is a list of currently open sockets, one
  for each ethernet interface and protocol (ICMP, ARP). This list
  is maintained by this and other ping functions.
  'ident' (in) is an identity value used for the ICMP 'id' field.

  Returns 0 if failed and !=0 if succeeded.

  Prerequisites (apart from the obvious):
  * 'rawsockets' needs to be initialized
  * syslog() is used, so openlog() before calling this
  */
int send_icmpping(socketnode *rawsockets, usernode user, int ident);

/*
  Check a received packet (in 'buf' (in), size 'len' (in)) from
  'from' (in) and if it is an ICMP echo reply from one of our clients
  and its ICMP 'id' field matches 'ident' (in), update the 'last_received'
  field in its node in 'users' (in/out).

  Returns 0 if failed and !=0 if succeeded.

  Prerequisites (apart from the obvious):
  * syslog() is used, so openlog() before calling this
  */

int recv_icmpreply(unsigned char *buf,
		   int len,
		   struct sockaddr_in *from,
		   usernode users,
		   int ident);
