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

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#include "config.h"
#include "socketnode.h"
#include "usernode.h"
#include "mymalloc.h"

#include "trace.h"
 
/*
  Most of this code was adapted from Mike Muuss' 'ping' program.
  No local variables were hurt in creating this code.
  */ 

#define ICMPDATALEN      (64 - ICMP_MINLEN)

/*
 * in_cksum
 *
 * Checksum routine for Internet Protocol family headers (C version)
 */
static u_int16_t in_cksum(u_int16_t *addr, int len)
{
  int nleft = len;
  u_int16_t *w = addr;
  u_int32_t sum = 0;
  u_int16_t answer = 0;
  
  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
  
  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    {
      answer=0;
      *(u_char *)(&answer) = *(u_char *)w ;
      sum += answer;
    }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
  sum += (sum >> 16);                     /* add carry */
  answer = ~sum;                          /* truncate to 16 bits */
  return(answer);
}

/*
  We just build an ICMP 'echo request' packet from scratch and send it
  out on the given socket. Most of the options and payload stuff from
  the 'ping' program has been removed and global variables have been
  made local.
  */
int send_ICMP_echo_request(int socket, struct in_addr *address, struct in_addr *source_address, int ident)
{
  static u_int8_t outpack[IP_MAXPACKET];
  struct icmp *icp=(struct icmp*)outpack;
  size_t packlen;
  int sentlen;
  struct sockaddr_in whereto;
  static long ntransmitted=0;

  icp->icmp_type = ICMP_ECHO;
  icp->icmp_code = 0;
  icp->icmp_cksum = 0;
  icp->icmp_seq = ntransmitted++;
  icp->icmp_id = ident;

  memset(&whereto, 0, sizeof(whereto));
  whereto.sin_family=AF_INET;
  memcpy(&whereto.sin_addr, address, sizeof(whereto.sin_addr));

  /* get total length of outpack (ICMPDATALEN is total length of payload) */
  packlen = ICMPDATALEN + (icp->icmp_data - outpack);

  /* compute ICMP checksum here */
  icp->icmp_cksum = in_cksum((u_short *)outpack, packlen);

  sentlen = sendto(socket, outpack, packlen, 0,
		   (struct sockaddr *)&whereto, sizeof(whereto));
  if (sentlen != (int)packlen)
    {
      if (sentlen < 0)
	{
	  syslog(LOG_ERR, "send_ICMP_echo_request(): sendto(): %m");
	  return 0;
	}
      else
	{
	  syslog(LOG_ERR, "send_ICMP_echo_request(): sendto(): short send");
	  return 0;
	}
    }
  return 1;
}

/*
  First, check if there is already an open socket available in 'rawsockets'
  for the interface used for this user (and for ICMP ping). If not, open
  a new one and add it to 'rawsockets'.

  Socket creation code and other stuff was copied from the original
  'ping' code (see above).
  */
int send_icmpping(socketnode *rawsockets, usernode user, int ident)
{
  socketnode tmpsock;
#if 0
  int alen;
#endif

  tmpsock=*rawsockets;
  while (tmpsock &&
	 ((tmpsock->ifindex != user->ifindex) ||
	  (tmpsock->type != user->user_type)))
    tmpsock = tmpsock->next;

  if (!tmpsock)
    {
      mymalloc_setperm();
      if (!(tmpsock=(socketnode)malloc(sizeof(struct socknode))))
	{
	  syslog(LOG_ERR, "malloc(): %m");
	  return 0;
	}
      mymalloc_resetperm();
      tmpsock->ifindex=user->ifindex;
      tmpsock->type=user->user_type;
      if ((tmpsock->socket = socket(AF_INET, SOCK_RAW, 1)) < 0)
	{
	  syslog(LOG_ERR, "socket(): %m");
	  free(tmpsock);
	  return 0;
	}

#if 0
      alen=65536;
      if (setsockopt(tmpsock->socket, SOL_SOCKET,
		     SO_RCVBUF, &alen, sizeof(alen)))
	{
	  syslog(LOG_ERR, "setsockopt(RCVBUF): %m");
	}
#endif
      syslog(LOG_NOTICE,"Creating new ICMP PING socket %d for ifindex %d\n",
	      tmpsock->socket,tmpsock->ifindex);

      tmpsock->next=*rawsockets;
      (*rawsockets)=tmpsock;
    }

  return send_ICMP_echo_request(tmpsock->socket, &(user->address), &(user->source_address), ident);
}

/*
  After making sure that this is a valid ICMP echo reply to one of our
  requests, find the relevant 'user' in 'users' and update its
  'last_received' value.
  Most of this code is copied and adapted from the original 'ping'
  program (see above).
  */
int recv_icmpreply(unsigned char *buf,
		   int len,
		   struct sockaddr_in *from,
		   usernode users,
		   int ident)
{
  struct ip *inpack_ip = (struct ip *)buf;
  int ipoptlen;
  struct icmp *inpack_icmp;
  int hlen;
  
  usernode tmpsubj;

  char tmpbuf[8192];

  if ((hlen=(inpack_ip->ip_hl) << 2) < sizeof(struct ip))
    {
      trace_msg("ICMP: Short packet (1)");
      return 0;
    }

  if (hlen>len)
    {
      trace_msg("ICMP: Long packet (1)");
      return 0;
    }

  ipoptlen = hlen - sizeof(struct ip);
  len-=hlen;
  inpack_icmp = (struct icmp *)(buf + sizeof(struct ip) + ipoptlen);
  
  if (len < ICMP_MINLEN + ICMPDATALEN)
    {
      trace_msg("ICMP: Short packet (2)");
      return 0;
    }

  if (inpack_icmp->icmp_type != ICMP_ECHOREPLY)
    {
      trace_msg("ICMP: Wrong packet type");
      return 0;
    }

  if (inpack_icmp->icmp_id != ident)
    {
      trace_msg("ICMP: Wrong ident");
      return 0;
    }

  sprintf(tmpbuf,"ICMP echo reply from %s",inet_ntoa(from->sin_addr));

  if (!(tmpsubj=findUser(users, &(from->sin_addr))))
    {
      strcat(tmpbuf," - unwanted");
      trace_msg(tmpbuf);
      return 0;
    }

  /* Check that this user is supposed to be checked with icmp */
  if (tmpsubj->user_type!=USER_TYPE_PING)
    {
      strcat(tmpbuf," - wrong user type");
      trace_msg(tmpbuf);
      return 0;
    }

  trace_msg(tmpbuf);

  tmpsubj->last_received=time(NULL);
  return 1;
}

