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
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
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
      fprintf(stderr, "[ARP] timeout - no reply received\n");
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
      printf("Received ARP reply from %02x", he.sll_addr[0]);
      for (i=1; i<he.sll_halen; i++)
	printf(":%02x", he.sll_addr[i]);
      printf(" to %02x", me.sll_addr[0]);
      for (i=1; i<me.sll_halen; i++)
	printf(":%02x", me.sll_addr[i]);
      printf("!\n");

      if (me.sll_family != AF_PACKET)
	printf("me: sll_family: %d\n", me.sll_family);
      if (me.sll_protocol != htons(ETH_P_ARP))
	printf("me: sll_protocol: %d\n", me.sll_protocol);
      if (me.sll_hatype!=ARPHRD_ETHER)
	printf("me: sll_hatype: %d\n", me.sll_hatype);
      if (me.sll_halen!=6)
	printf("me: sll_halen: %d\n", me.sll_halen);

      if (he.sll_family != AF_PACKET)
	printf("he: sll_family: %d\n", he.sll_family);
      if (he.sll_protocol != htons(ETH_P_ARP))
	printf("he: sll_protocol: %d\n", he.sll_protocol);
      if (he.sll_hatype!=ARPHRD_ETHER)
	printf("he: sll_hatype: %d\n", he.sll_hatype);
      if (he.sll_halen!=6)
	printf("he: sll_halen: %d\n", he.sll_halen);
    }
  else
    {
      close(s);
      return 0;
    }

  close(s);
  return 1;
}

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
int do_icmpprobe(struct in_addr *src, struct in_addr *dst)
{
  static u_int8_t outpack[IP_MAXPACKET];
  struct icmp *icp=(struct icmp*)outpack;
  size_t packlen;
  int sentlen;
  struct sockaddr_in whereto;
  struct sockaddr_in reply_source;
  static long ntransmitted=0;
  int s;
  static u_int16_t ident=0xa5;

  int alen;
  static char packet[8192];
  struct ip *inpack_ip = (struct ip *)packet;
  int ipoptlen;
  struct icmp *inpack_icmp;
  int hlen;

  int r;
  int len;
  int reply_received;

  time_t start, end;

  fd_set myfdset;
  struct timeval select_timeout={5, 0};

  if ((s = socket(AF_INET, SOCK_RAW, 1)) < 0)
    {
      perror("[ICMP] socket()");
      return 0;
    }

  icp->icmp_type = ICMP_ECHO;
  icp->icmp_code = 0;
  icp->icmp_cksum = 0;
  icp->icmp_seq = ntransmitted++;
  icp->icmp_id = ident;

  memset(&whereto, 0, sizeof(whereto));
  whereto.sin_family=AF_INET;
  memcpy(&whereto.sin_addr, dst, sizeof(whereto.sin_addr));

  /* get total length of outpack (ICMPDATALEN is total length of payload) */
  packlen = ICMPDATALEN + (icp->icmp_data - outpack);

  /* compute ICMP checksum here */
  icp->icmp_cksum = in_cksum((u_short *)outpack, packlen);

  sentlen = sendto(s, outpack, packlen, 0,
		   (struct sockaddr *)&whereto, sizeof(whereto));
  if (sentlen != (int)packlen)
    {
      if (sentlen < 0)
	{
	  perror("[ICMP] sendto()");
	  close(s);
	  return 0;
	}
      else
	{
	  fprintf(stderr, "[ICMP] sendto(): short send\n");
	  close(s);
	  return 0;
	}
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
      alen=sizeof(struct sockaddr_in);
      if ((len=recvfrom(s, packet, sizeof(packet), 0,
			(struct sockaddr *)(&reply_source), &alen))<0)
	{
	  perror("[ICMP] recvfrom()");
	  continue;
	}

      if ((hlen=(inpack_ip->ip_hl) << 2) < sizeof(struct ip))
	{
	  fprintf(stderr, "[ICMP] Short packet (1)\n");
	  continue;
	}

      if (hlen>len)
	{
	  fprintf(stderr,"[ICMP] Long packet (1)\n");
	  continue;
	}

      ipoptlen = hlen - sizeof(struct ip);
      len-=hlen;
      inpack_icmp = (struct icmp *)(packet + sizeof(struct ip) + ipoptlen);
  
      if (len < ICMP_MINLEN + ICMPDATALEN)
	{
	  fprintf(stderr, "[ICMP] Short packet (2)\n");
	  continue;
	}

      if (inpack_icmp->icmp_type != ICMP_ECHOREPLY)
	{
	  fprintf(stderr, "[ICMP] Wrong packet type %d\n", inpack_icmp->icmp_type);
	  continue;
	}

      if (inpack_icmp->icmp_id != ident)
	{
	  fprintf(stderr, "[ICMP] Wrong ident in ICMP reply %04x\n", inpack_icmp->icmp_id);
	  continue;
	}

      if (memcmp(&(reply_source.sin_addr.s_addr), &(dst->s_addr), sizeof(reply_source.sin_addr.s_addr)))
	{
	  fprintf(stderr, "[ICMP] Wrong source address in ICMP reply: %s\n", inet_ntoa(reply_source.sin_addr));
	  continue;
	}

      reply_received=1;
      break;
    }

  ident++;

  if (!reply_received)
    {
      fprintf(stderr, "[ICMP] timeout - no reply received\n");
      return 0;
    }

  printf("Received ICMP echo reply from %s to ", inet_ntoa(reply_source.sin_addr));
  printf("%s!\n", inet_ntoa(*src));
  return 1;
}

void usage(char *progname)
{
  fprintf(stderr, "Usage: %s [-n <probe count>] [-d <inter-packet delay>] <host> [<host> ...]\n", progname);
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
  int i, t, r, j;
  unsigned long repeat_count=1, interdelay=50;
  int o;
  static char typetext[32], ip[64];
  static char tmpbuf[1024], tmpbuf2[1024];
  s.s_addr=INADDR_ANY;
  openlog("test_netlink", LOG_PERROR|LOG_PID, LOG_USER);
  while ((o=getopt(argc, argv, "n:d:"))!=-1)
    switch (o)
      {
      case 'n':
	repeat_count=atol(optarg);
	break;
      case 'd':
	interdelay=atol(optarg);
	break;
      default:
	usage(argv[0]);
	return -1;
	break;
      }

  printf("repeat count=%ld\ninter-packet delay=%ld\n", repeat_count, interdelay);
  for (i=optind; i<argc; i++)
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
	  printf("Checking %s:\n", argv[i]);
	  src=&s;
	  dst=&(((struct sockaddr_in *)(dest->ai_addr))->sin_addr);
	  getnameinfo(dest->ai_addr, dest->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
	  printf("IP address: %s\n", ip);
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
	      printf("Interface index %d, name %s, src addr=%s, type=%s\n",
		     idx, tmpbuf2, tmpbuf, typetext);
	      switch(t)
		{
		case USER_TYPE_ARPPING:
		  for (j=0; j<repeat_count; j++)
		    {
		      do_arpprobe(idx, src, dst);
		      if (interdelay)
			usleep(interdelay);
		    }
		  break;
		case USER_TYPE_PING:
		  for (j=0; j<repeat_count; j++)
		    {
		      do_icmpprobe(src, dst);
		      if (interdelay)
			usleep(interdelay);
		    }
		  break;
		}
	    }
	  else
	    printf("Error for address %s/%s: ret=%d\n",
		   argv[i], ip, idx);
	  printf("\n");
	}
    }
  closelog();
  return 0;
}
