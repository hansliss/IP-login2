#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <string.h>

#include "usernode.h"
#include "socketnode.h"
#include "mymalloc.h"

#include "trace.h"
 
/*
  We need to build an ARP request by hand here, and then sendto() it out
  on the socket.

  Most of this code was copied from the original IP-login code by Robert
  Olsson, SLU.
  */
int send_ARP_request(int socket_handle,
		     struct in_addr src,
		     struct in_addr dst,
		     struct sockaddr_ll *ME,
		     struct sockaddr_ll *HE)
{
  static unsigned char buf[256];
  struct arphdr *ah = (struct arphdr*)buf;
  unsigned char *p = (unsigned char *)(ah+1);

  ah->ar_hrd = htons(ME->sll_hatype);
  if (ah->ar_hrd == htons(ARPHRD_FDDI))
    ah->ar_hrd = htons(ARPHRD_ETHER);
  ah->ar_pro = htons(ETH_P_IP);
  ah->ar_hln = ME->sll_halen;
  ah->ar_pln = 4;
  ah->ar_op  = htons(ARPOP_REQUEST);
  memcpy(p, &(ME->sll_addr), ah->ar_hln);
  p+=ME->sll_halen;
  memcpy(p, &src, 4);
  p+=4;
  memcpy(p, &(HE->sll_addr), ah->ar_hln);
  p+=ah->ar_hln;

  memcpy(p, &dst, 4);
  p+=4;
  if (sendto(socket_handle, buf, p-buf,
	     0, (struct sockaddr*)HE,
	     sizeof(*HE)) == p-buf)
    return 1;
  else
    {
      syslog(LOG_ERR, "send_ARP_request(): sendto(): %m");
      return 0;
    }
}

/*
  First, check if there is already an open socket available in 'rawsockets'
  for the interface used for this user (and for ARPPING). If not, open
  a new one and add it to 'rawsockets'.

  Socket creation code and other stuff was copied from the original
  IP-login code by Robert Olsson, SLU.
  */

int send_arpping(socketnode *rawsockets, usernode user)
{
  struct sockaddr_ll *me;
  socketnode tmpsock;
  int alen;

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
      if ((tmpsock->socket = socket(PF_PACKET, SOCK_DGRAM, 0)) < 0)
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
      me=(struct sockaddr_ll *)(tmpsock->data);
      me->sll_family = AF_PACKET;
      me->sll_ifindex = user->ifindex;
      me->sll_protocol = htons(ETH_P_ARP);


      if (bind(tmpsock->socket, (struct sockaddr*)me,
	       sizeof(struct sockaddr_ll)) == -1)
	{
	  syslog(LOG_ERR, "bind(): %m");
	  return 0;
	}

      alen = sizeof(struct sockaddr_ll);
      if (getsockname(tmpsock->socket, (struct sockaddr*)me, &alen) == -1)
	{
	  syslog(LOG_ERR, "getsockname(): %m");
	  return 0;
	}
      
      if (me->sll_halen == 0)
	{
	  syslog(LOG_ERR,"Interface \"%d\" is not ARPable (no ll address)",
		 tmpsock->ifindex);
	  return 0;
	}

      syslog(LOG_NOTICE,"Creating new ARP PING socket %d for ifindex %d\n",
	      tmpsock->socket,tmpsock->ifindex);

      tmpsock->next=*rawsockets;
      (*rawsockets)=tmpsock;
    }

  me=(struct sockaddr_ll *)(tmpsock->data);
  if (user->ll_address_set==-1)
    {
      /*
	First time, we will send as broadcast. Sender
	address of first received reply will be copied
	here.
	*/
      memcpy(&(user->ll_address), me, sizeof(struct sockaddr_ll));
      memset(user->ll_address.sll_addr, -1, user->ll_address.sll_halen);
      user->ll_address_set=0;
    }
  return send_ARP_request(tmpsock->socket, user->source_address,
			  user->address, me, &(user->ll_address));
}

/*
  After making sure that this is a valid ARP reply to one of our requests,
  find the relevant 'user' in 'users' and update its 'last_received'
  value.
  Most of this code (and comments :-) is copied from the original IP-login
  code by Robert Olsson, SLU.
  */
int recv_arpreply(unsigned char *buf, int len,
		  struct sockaddr_ll *from, usernode users)
{
  struct arphdr *ah = (struct arphdr*)buf;
  unsigned char *p = (unsigned char *)(ah+1);
  struct in_addr src_ip, dst_ip;
  usernode tmpsubj;
  char tmpbuf[8192];

  /* Filter out wild packets */
  if (from->sll_pkttype != PACKET_HOST &&
      from->sll_pkttype != PACKET_BROADCAST &&
      from->sll_pkttype != PACKET_MULTICAST)
    return 0;

  /* Only these types are recognised */
  if (ah->ar_op != htons(ARPOP_REQUEST) &&
      ah->ar_op != htons(ARPOP_REPLY))
    return 0;

  /* ARPHRD check and this fucking FDDI hack here :-( */
  if (ah->ar_hrd != htons(from->sll_hatype) &&
      (from->sll_hatype != ARPHRD_FDDI || ah->ar_hrd != htons(ARPHRD_ETHER)))
    return 0;

  /* Protocol must be IP. */
  if (ah->ar_pro != htons(ETH_P_IP))
    return 0;

  if (ah->ar_pln != 4)
    return 0;

  if (len < sizeof(*ah) + 2*(4 + ah->ar_hln))
    return 0;

  memcpy(&src_ip, p+ah->ar_hln, 4);
  memcpy(&dst_ip, p+ah->ar_hln+4+ah->ar_hln, 4);

  sprintf(tmpbuf,"ARP reply from %s",inet_ntoa(src_ip));

  if (!(tmpsubj=findUser(users, &src_ip)))
    {
      strcat(tmpbuf," - unwanted");
      trace_msg(tmpbuf);
      return 0;
    }

  if (memcmp(&(tmpsubj->source_address), &dst_ip, sizeof(struct in_addr)))
    {
#if 0
      syslog(LOG_ERR, "Spoofed ARP reply received from %s to %s",
	     inet_ntoa(src_ip), inet_ntoa(dst_ip));
#endif
      strcat(tmpbuf," - wrong source; spoofed?");
      trace_msg(tmpbuf);
      return 0;
    }

  /* Check that this user is supposed to be checked with arpping */
  if (tmpsubj->user_type!=USER_TYPE_ARPPING)
    {
      strcat(tmpbuf," - wrong user type");
      trace_msg(tmpbuf);
      return 0;
    }

  if (!tmpsubj->ll_address_set)
    {
      memcpy(tmpsubj->ll_address.sll_addr, p, from->sll_halen);
      tmpsubj->ll_address_set=1;
    }
  

  trace_msg(tmpbuf);

  tmpsubj->last_received=time(NULL);

  return 1;
}

