#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <time.h>

#include "autoconfig.h"
#include <hl.h>
#include "iplogin2.h"
#include "find_interface.h"

int arpprobe(int s, struct in_addr *src, struct in_addr *dst, struct sockaddr_ll *me, struct sockaddr_ll *he)
{
  int r;

  static unsigned char buf[256];
  struct arphdr *ah = (struct arphdr*)buf;
  unsigned char *p = (unsigned char *)(ah+1); /* Points directly after the basic arphdr */

  struct in_addr src_ip, dst_ip;

  int alen;
  static char packet[8192];

  int len;
  int reply_received;

  time_t start, end;

  fd_set myfdset;
  struct timeval select_timeout={5, 0};

  ah->ar_hrd = htons(me->sll_hatype);
  if (ah->ar_hrd == htons(ARPHRD_FDDI))
    ah->ar_hrd = htons(ARPHRD_ETHER);
  ah->ar_pro = htons(ETH_P_IP);
  ah->ar_hln = me->sll_halen;
  ah->ar_pln = 4;
  ah->ar_op  = htons(ARPOP_REQUEST);
  memcpy(p, &(me->sll_addr), ah->ar_hln);
  p+=me->sll_halen;
  memcpy(p, src, 4);
  p+=4;
  memcpy(p, &(he->sll_addr), ah->ar_hln);
  p+=ah->ar_hln;

  memcpy(p, dst, 4);
  p+=4;

  if (sendto(s, buf, p-buf, 0, (struct sockaddr*)he,
	     sizeof(*he)) != p-buf)
    {
      perror("[ARP] sendto()");
      return 0;
    }

  time(&start);

  reply_received=0;
  while (time(&end)-start < 5)
    {
      FD_ZERO(&myfdset);
      FD_SET(s, &myfdset);
      if (!(r=select(s+1, &myfdset, NULL, NULL, &select_timeout)))
	{
	  fprintf(stderr, "[ARP] select() timeout\n");
	  continue;
	}
      if (r == -1)
	{
	  perror("[ARP] select()");
	  continue;
	}
      alen=sizeof(struct sockaddr_ll);
      if ((len=recvfrom(s, packet, sizeof(packet), 0,
		   (struct sockaddr *)he, &alen))<0)
	{
	  perror("[ARP] recvfrom()");
	  continue;
	}

      /* Filter out wild packets */
      if (he->sll_pkttype != PACKET_HOST &&
	  he->sll_pkttype != PACKET_BROADCAST &&
	  he->sll_pkttype != PACKET_MULTICAST)
	{
	  fprintf(stderr, "Wrong packet type in reply\n");
	  continue;
	}

      /* Only these types are recognised */
      if (ah->ar_op != htons(ARPOP_REQUEST) &&
	  ah->ar_op != htons(ARPOP_REPLY))
	{
	  fprintf(stderr, "Wrong ARP message type in reply\n");
	  continue;
	}

      /* ARPHRD check and this fucking FDDI hack here :-( */
      if (ah->ar_hrd != htons(he->sll_hatype) &&
	  (he->sll_hatype != ARPHRD_FDDI || ah->ar_hrd != htons(ARPHRD_ETHER)))
	{
	  fprintf(stderr, "Wrong ARP hardware address type in reply\n");
	  continue;
	}

      /* Protocol must be IP. */
      if (ah->ar_pro != htons(ETH_P_IP))
	{
	  fprintf(stderr, "Wrong protocol type in ARP reply\n");
	  continue;
	}

      if (ah->ar_pln != 4)
	{
	  fprintf(stderr, "Wrong protocol address length in ARP reply\n");
	  continue;
	}

      if (len < sizeof(*ah) + 2*(4 + ah->ar_hln))
	{
	  fprintf(stderr, "Wrong reply length in ARP reply\n");
	  continue;
	}

      p=(unsigned char *)(ah+1);
      memcpy(&dst_ip, p+ah->ar_hln, 4);
      memcpy(&src_ip, p+ah->ar_hln+4+ah->ar_hln, 4);

      if (memcmp(&(src_ip.s_addr), &(dst->s_addr), sizeof(src_ip.s_addr))!=0 ||
	  memcmp(&(dst_ip.s_addr), &(src->s_addr), sizeof(dst_ip.s_addr))!=0)
	{
	  fprintf(stderr, "[ARP] Wrong source/destination in reply: %s to ", inet_ntoa(src_ip));
	  fprintf(stderr, "%s\n", inet_ntoa(dst_ip));
	  continue;
	}

      reply_received=1;
      break;
    }

  if (!reply_received)
    {
      fprintf(stderr, "[ARP] arpprobe() timeout - no reply received\n");
      return 0;
    }

  return 1;
}

int do_arpprobe(int ifindex, struct in_addr *src, struct in_addr *dst)
{
  int s, i;
  struct sockaddr_ll me;
  struct sockaddr_ll he;
  int alen;

  if ((s = socket(PF_PACKET, SOCK_DGRAM, 0)) < 0)
    {
      perror("[ARP] socket()");
      return 0;
    }

  me.sll_family = AF_PACKET;
  me.sll_ifindex = ifindex;
  me.sll_protocol = htons(ETH_P_ARP);

  if (bind(s, (struct sockaddr*)(&me),
	   sizeof(struct sockaddr_ll)) == -1)
    {
      perror("[ARP] bind()");
      close(s);
      return 0;
    }

  alen = sizeof(struct sockaddr_ll);
  if (getsockname(s, (struct sockaddr*)(&me), &alen) == -1)
    {
      perror("[ARP] getsockname()");
      close(s);
      return 0;
    }
      
  if (me.sll_halen == 0)
    {
      fprintf(stderr, "[ARP] Interface \"%d\" is not ARPable (no ll address)\n", ifindex);
      close(s);
      return 0;
    }

  /*
    First time, we will send as broadcast. Sender
    address of first received reply will be copied
    here.
    */
  memcpy(&he, &me, sizeof(struct sockaddr_ll));
  memset(he.sll_addr, -1, he.sll_halen);
  if (arpprobe(s, src, dst, &me, &he) &&
      arpprobe(s, src, dst, &me, &he))
    {
      printf("Received ARP reply!\n");
      printf("Me:\n---\n");
      if (me.sll_family != AF_PACKET)
	printf("sll_family: %d\n", me.sll_family);
      if (me.sll_protocol != htons(ETH_P_ARP))
	printf("sll_protocol: %d\n", me.sll_protocol);
      if (me.sll_hatype!=ARPHRD_ETHER)
	printf("sll_hatype: %d\n", me.sll_hatype);
      if (me.sll_halen!=6)
	printf("sll_halen: %d\n", me.sll_halen);
      printf("MAC address: %02x", me.sll_addr[0]);
      for (i=1; i<me.sll_halen; i++)
	printf(":%02x", me.sll_addr[i]);
      printf("\n");

      printf("\n");
      printf("He:\n---\n");
      if (he.sll_family != AF_PACKET)
	printf("sll_family: %d\n", he.sll_family);
      if (he.sll_protocol != htons(ETH_P_ARP))
	printf("sll_protocol: %d\n", he.sll_protocol);
      if (he.sll_hatype!=ARPHRD_ETHER)
	printf("sll_hatype: %d\n", he.sll_hatype);
      if (he.sll_halen!=6)
	printf("sll_halen: %d\n", he.sll_halen);
      printf("MAC address: %02x", he.sll_addr[0]);
      for (i=1; i<he.sll_halen; i++)
	printf(":%02x", he.sll_addr[i]);
      printf("\n");
    }
  else
    {
      close(s);
      return 0;
    }

  close(s);
  return 1;
}

int main(int argc, char *argv[])
{
  struct in_addr s;
  struct in_addr *src, *dst;
  struct addrinfo *dest;
  struct addrinfo hints={0,
                         PF_UNSPEC,
			 SOCK_STREAM,
                         IPPROTO_TCP,
                         0, NULL, NULL, NULL};
  int idx;
  int i, t, r;
  static char typetext[32], ip[64];
  static char tmpbuf[1024], tmpbuf2[1024];
  s.s_addr=INADDR_ANY;
  openlog("test_netlink", LOG_PERROR|LOG_PID, LOG_USER);
  for (i=1; i<argc; i++)
    {
      if ((r=getaddrinfo(argv[i], NULL, &hints, &dest))!=0)
	{
	  if (r==EAI_SYSTEM)
	    perror("getaddrinfo()");
	  else
	    fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(r));
	}
      else if (dest->ai_family != PF_INET)
	fprintf(stderr, "Wrong address family, only IPv4 supported\n");
      else
	{
	  src=&s;
	  dst=&(((struct sockaddr_in *)(dest->ai_addr))->sin_addr);
	  getnameinfo(dest->ai_addr, dest->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
	  idx = find_interface(&(((struct sockaddr_in *)(dest->ai_addr))->sin_addr), &s, tmpbuf2, sizeof(tmpbuf2));
	  if (idx >= 0)
	    {
	      switch((t=determine_type(&(((struct sockaddr_in *)(dest->ai_addr))->sin_addr), NULL)))
		{
		case USER_TYPE_NONE:
		  strcpy(typetext, "(none)");
		  break;
		case USER_TYPE_ARPPING:
		  strcpy(typetext, "ARP");
		  break;
		case USER_TYPE_PING:
		  strcpy(typetext, "ICMP");
		  break;
		default:
		  sprintf(typetext, "<%d>", t);
		  break;
		}
	      strcpy(tmpbuf,inet_ntoa(s));
	      printf("%s/%s: Interface index %d, name %s, src addr=%s, type=%s\n",
		     argv[i], ip, idx, tmpbuf2, tmpbuf, typetext);
	      switch(t)
		{
		case USER_TYPE_ARPPING:
		  do_arpprobe(idx, src, dst);
		  break;
		}
	    }
	  else
	    printf("Error for address %s/%s: ret=%d\n",
		   argv[i], ip, idx);
	}
    }
  closelog();
  return 0;
}
