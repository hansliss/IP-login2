#include <stdio.h>
#include <stdlib.h>

#ifndef WIN32
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "config.h"
#include <errno.h>
#endif

#include <time.h>
#include <sys/stat.h>

#if HAVE_STRINGS_H==1
#include <strings.h>
#endif
#if HAVE_STRING_H==1
#include <string.h>
#endif
#include "hl.h"

#ifndef WIN32
int getLastSockErr() { return errno; }
#define INTERRUPTED EINTR
#else
int getLastSockErr() { return WSAGetLastError(); }
#define INTERRUPTED WSAEINTR
#endif

#define READ_TIMEOUT 10000
#define BUFSIZE 8192


/* Authentication and encryption data */
unsigned char local_challenge[CHALLENGE_SIZE];
unsigned char remote_challenge[CHALLENGE_SIZE];
unsigned char local_streamkey[SHA_DIGEST_LENGTH];
unsigned char remote_streamkey[SHA_DIGEST_LENGTH];

/* Fill an array with random data */
void makerandom(unsigned char *buf, int bufsize)
{
  int i;
#ifdef WIN32
  HCRYPTPROV hCryptProv;
  srand((unsigned)clock());
  for( i = 0; i < bufsize;i++ )
    buf[i]=rand() % 0x100;
  if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL,0))
    CryptGenRandom(hCryptProv,bufsize,buf);
#else
  srand((unsigned)time( NULL ));
  for( i = 0; i < bufsize;i++ )
    buf[i]=rand() % 0x100;
#endif
}

int readblock(SOCKET fd, int timeout, unsigned char *buf, int count)
{
  fd_set fds;
  struct timeval tv;
  int n;
  static char readbuffer[BUFSIZE];
  static int data_in_buffer=0;
  while (data_in_buffer < count)
    {
      FD_ZERO(&fds);
      FD_SET(fd,&fds);
      tv.tv_sec=timeout/1000;
      tv.tv_usec=1000 * (timeout%1000);
      if ((n=select(fd+1, &fds, NULL, NULL, &tv)) > 0)
	{
	  if ((n=recv(fd,&(readbuffer[data_in_buffer]),
		      BUFSIZE-data_in_buffer, 0))>0)
	    {
	      data_in_buffer+=n;
	    }
	  else
	    {
	      if (n==0)
		return 0;
	      else
		if (getLastSockErr()!=INTERRUPTED)
		  {
		    syslog(LOG_ERR,"read(): %m");
		    return -1;
		  }
	    }
	}
      else
	{
	  if (n<0)
	    syslog(LOG_ERR,"select(): %m");
	  else
	    syslog(LOG_ERR,"select(): timeout");
	  return -1;
	}
    }
  memcpy(buf,readbuffer,count);
  if (data_in_buffer > count)
    memmove(readbuffer,&(readbuffer[count]),data_in_buffer-count);
  data_in_buffer-=count;
  return 1;
}

char *hlcrypt_MD4(unsigned char *string,int slen)
{
  MD4_CTX c;
  int i;
  unsigned char md[16];
  static char txtbuf[16*2+1];

  MD4Init(&c);
  MD4Update(&c,string,(unsigned long)slen);
  MD4Final(&(md[0]), &c);
#if 0
  for (i=0; i<16; i++)
    sprintf(&(txtbuf[i*2]),"%02x",md[i]);
#endif
  for (i=0; i<16; i++)
    txtbuf[i]=md[i];
  return txtbuf;
}

char *hlcrypt_MD5(unsigned char *string,int slen)
{
  MD5_CTX c;
  int i;
  unsigned char md[16];
  static char txtbuf[16*2+1];

  MD5Init(&c);
  MD5Update(&c,string,(unsigned long)slen);
  MD5Final(&(md[0]), &c);
#if 0
  for (i=0; i<16; i++)
    sprintf(&(txtbuf[i*2]),"%02x",md[i]);
#endif
  for (i=0; i<16; i++)
    txtbuf[i]=md[i];
  return txtbuf;
}

char *hlcrypt_SHA1(unsigned char *string,int slen)
{
  SHA1Context c;
  int i;
  unsigned char md[SHA_DIGEST_LENGTH];
  static char txtbuf[SHA_DIGEST_LENGTH*2+1];

  SHA1Reset(&c);
  SHA1Input(&c,string,(unsigned long)slen);
  SHA1Result(&c, &(md[0]));
#if 0
  for (i=0; i<SHA_DIGEST_LENGTH; i++)
    sprintf(&(txtbuf[i*2]),"%02x",md[i]);
#endif
  for (i=0; i<SHA_DIGEST_LENGTH; i++)
    txtbuf[i]=md[i];
  return txtbuf;
}

int hlcrypt_MakeToken(char *buf, int bufsize)
{
  int i;
  unsigned char tmpbuf[CHALLENGE_SIZE], *c;
  if (bufsize < (SHA_DIGEST_LENGTH*2+1))
    return 0;
  makerandom(tmpbuf,CHALLENGE_SIZE);
  c=hlcrypt_SHA1(tmpbuf, CHALLENGE_SIZE);
  if (c)
    {
      for (i=0;i<SHA_DIGEST_LENGTH;i++)
	sprintf(&(buf[i*2]),"%02x",c[i]);
      buf[SHA_DIGEST_LENGTH*2]='\0';
      return 1;
    }
  else
    return 0;
}

/* buf[] MUST be at least SHA_DIGEST_LENGTH large. */

void makekey(unsigned char *buf, int bufsize,
	     unsigned char *one, int onesize,
	     unsigned char *two, int twosize)
{
  static unsigned char tmpbuf[BUFSIZE];
  unsigned char *c;
  if (bufsize < SHA_DIGEST_LENGTH)
    return;
  memcpy(tmpbuf, one, onesize);
  memcpy(&(tmpbuf[onesize]),two,twosize);
  c=hlcrypt_SHA1(tmpbuf, onesize + twosize);
  if (c)
    memcpy(buf,c,SHA_DIGEST_LENGTH);
}

/* Encrypt and send a string as a series of packets.
   Keep the terminating NUL */
int hlcrypt_Send(SOCKET s, unsigned char *string, HLCRYPT_HANDLE h)
{
  int i, j, n, m;
  unsigned char tmpbuf[BUFSIZE];
  unsigned char packet[PSIZE];
  unsigned char *lc, *lk;
  n=strlen(string)+1;

  if (h)
    {
      lc=h->local_challenge;
      lk=h->local_streamkey;
    }
  else
    {
      lc=local_challenge;
      lk=local_streamkey;      
    }
  /*  Split the string in packets of size PSIZE */
  for (i=0; i<n; i+=PSIZE)
    {
      strncpy(packet,&(string[i]),PSIZE);
      m=n-i;

      /* Fill the last one with random data */
      while (m<PSIZE)
	packet[m++]=rand() % 0x100;

      /* Calculate a new stream key before this cleartext is encrypted */
      makekey(tmpbuf, sizeof(tmpbuf), lc,
	      CHALLENGE_SIZE, packet, PSIZE);

      /* Encrypt this packet */
      for (j=0; j<PSIZE; j++)
	packet[j]^=lk[j];

      /* ...and write it to the socket */
      send(s, packet, PSIZE, 0);

      /* Save the new key */
      memcpy(lk, tmpbuf, KEYSIZE);
    }
  return 1;
}

/* Get a complete NUL-terminated string withing a specified timeout */
int hlcrypt_Receive(SOCKET s, unsigned char *string, int maxlen, int timeout, HLCRYPT_HANDLE h)
{
  int ready=0;
  int i,j,n;
  unsigned char packet[PSIZE];
  unsigned char *rc, *rk;

  if (h)
    {
      rc=h->remote_challenge;
      rk=h->remote_streamkey;
    }
  else
    {
      rc=remote_challenge;
      rk=remote_streamkey;      
    }
  i=0;
  /* Loop until a NUL is found in the cleartext */
  while (!ready)
    {
      if (readblock(s, timeout, packet, PSIZE) > 0)
	{
	  /* Decrypt this packet */
	  for (j=0;j<PSIZE;j++)
	    packet[j]^=rk[j];

	  /* Calculate a new stream key */
	  makekey(rk, KEYSIZE, 
		  rc, CHALLENGE_SIZE,
		  packet, PSIZE);

	  /* Check if a NUL has been received. */
	  if (memchr(packet,'\0',PSIZE))
	    {
	      n=strlen(packet)+1;
	      ready=1;
	    }
	  else
	    n=PSIZE;

	  /* Copy the cleartext */
	  if ((i + n) < maxlen)
	    memcpy(&(string[i]),packet,n);
	  else
	    return -3; /* Not enough space */
	  i+=n;
	}
      else
	return -1; /* timeout or connection closed */
    }
  return i;
}


int hlcrypt_AuthClient(SOCKET csocket, unsigned char *local_key,
		       unsigned char *remote_key, HLCRYPT_HANDLE *h)
{
  char tmpbuf[BUFSIZE], tmpbuf2[SHA_DIGEST_LENGTH];
  char *lc, *lk, *rc, *rk;
  if (h)
    {
      (*h)=(HLCRYPT_HANDLE)malloc(sizeof(struct hlcrypt_handle_s));
      lc=(*h)->local_challenge;
      lk=(*h)->local_streamkey;
      rc=(*h)->remote_challenge;
      rk=(*h)->remote_streamkey;
    }
  else
    {
      lc=local_challenge;
      lk=local_streamkey;
      rc=remote_challenge;
      rk=remote_streamkey;
    }      
      
  /* Generate a client challenge */
  makerandom(lc, CHALLENGE_SIZE);

  /* Write the server challenge to the socket */
  send(csocket, lc, CHALLENGE_SIZE, 0);

  if (readblock(csocket, READ_TIMEOUT, tmpbuf2, SHA_DIGEST_LENGTH) <= 0)
    {
      syslog(LOG_ERR,"No response received");
      return 0;
    }

  makekey(tmpbuf, sizeof(tmpbuf), lc,
	  CHALLENGE_SIZE, remote_key, strlen(remote_key));

  if (memcmp(tmpbuf2, tmpbuf,SHA_DIGEST_LENGTH)!=0)
    {
      syslog(LOG_ERR,
	     "Authentication failed. Wrong response to client challenge");
      return 0;
    }

  makekey(lk, KEYSIZE,
	  lc, CHALLENGE_SIZE,
	  local_key, strlen(local_key));

  if (readblock(csocket, READ_TIMEOUT, tmpbuf, CHALLENGE_SIZE) <= 0)
    {
      syslog(LOG_ERR,"Authentication failed. No server challenge received");
      return 0;
    }

  memcpy(rc, tmpbuf,CHALLENGE_SIZE);

  makekey(tmpbuf, sizeof(tmpbuf),
	  rc, CHALLENGE_SIZE,
	  local_key, strlen(local_key));

  send(csocket, tmpbuf, SHA_DIGEST_LENGTH, 0);

  makekey(rk, KEYSIZE,
	  rc, CHALLENGE_SIZE,
	  remote_key, strlen(remote_key));

  if ((hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h?(*h):NULL)>0) &&
      (!strncmp(tmpbuf, "OK", 2)))
    {
      syslog(LOG_INFO,"Authenticated");
      return 1;
    }
  else
    return 0;
}

int hlcrypt_AuthServer(SOCKET csocket, unsigned char *remote_key,
		       unsigned char *local_key, HLCRYPT_HANDLE *h)
{
  char tmpbuf[BUFSIZE], tmpbuf2[SHA_DIGEST_LENGTH];
  char *lc, *lk, *rc, *rk;
  if (h)
    {
      (*h)=(HLCRYPT_HANDLE)malloc(sizeof(struct hlcrypt_handle_s));
      lc=(*h)->local_challenge;
      lk=(*h)->local_streamkey;
      rc=(*h)->remote_challenge;
      rk=(*h)->remote_streamkey;
    }
  else
    {
      lc=local_challenge;
      lk=local_streamkey;
      rc=remote_challenge;
      rk=remote_streamkey;
    }      
      
  if (readblock(csocket, READ_TIMEOUT, tmpbuf, CHALLENGE_SIZE) <= 0)
    {
      syslog(LOG_ERR,"No challenge received");
      return 0;
    }

  /* Generate a server challenge and save the client challenge */
  makerandom(lc, CHALLENGE_SIZE);
  memcpy(rc, tmpbuf, CHALLENGE_SIZE);

  /* Calculate and send the response */
  makekey(tmpbuf, sizeof(tmpbuf), rc,
	  CHALLENGE_SIZE, local_key, strlen(local_key));
  send(csocket, tmpbuf, SHA_DIGEST_LENGTH,0);

  /* Write the server challenge to the socket */
  send(csocket, lc, CHALLENGE_SIZE, 0);

  if (readblock(csocket, READ_TIMEOUT, tmpbuf2, SHA_DIGEST_LENGTH) <= 0)
    {
      syslog(LOG_ERR,"No response received");
      return 0;
    }

  makekey(tmpbuf, sizeof(tmpbuf), lc, CHALLENGE_SIZE,
	  remote_key, strlen(remote_key));

  if (memcmp(tmpbuf2,tmpbuf,SHA_DIGEST_LENGTH)!=0)
    {
      syslog(LOG_ERR,
	     "Authentication failed. Wrong response to server challenge");
      return 0;
    }

  makekey(lk, KEYSIZE,
	  lc,CHALLENGE_SIZE,
	  local_key, strlen(local_key));
  makekey(rk, KEYSIZE,
	  rc, CHALLENGE_SIZE,
	  remote_key, strlen(remote_key));

  strcpy(tmpbuf,"OK");
  hlcrypt_MakeToken(tmpbuf+2,sizeof(tmpbuf)-2);
  
  hlcrypt_Send(csocket,tmpbuf, h?(*h):NULL);

  return 1;
}

/*
  Free a handle structure
  */
int hlcrypt_freeHandle(HLCRYPT_HANDLE *h)
{
  if (h && (*h))
    {
      free(*h);
      *h=NULL;
    }
  return 1;
}

