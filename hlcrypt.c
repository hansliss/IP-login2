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
#include "rsaref_global.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "uu_aes.h"
#include "hlcrypt.h"

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
	    {
	      if (errno == EINTR)
		continue;
	      syslog(LOG_ERR,"hlcrypt::readblock(): select(): %m");
	    }
	  else
	    syslog(LOG_ERR,"hlcrypt::readblock(): select(): timeout");
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
  static unsigned char tmpbuf[BUFSIZE];
  static unsigned char tmpbuf2[BUFSIZE];
  unsigned char packet[PSIZE];
  unsigned char *lc, *lk;

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
  if (h && (h->encryption==ENCRYPTION_AES))
    {
      strncpy(tmpbuf, string, sizeof(tmpbuf));
      i=uu_aes_encrypt(tmpbuf, strlen(tmpbuf), h->aes_key, 256, tmpbuf2, sizeof(tmpbuf2), NULL);
#ifdef DEBUG
      if (i)
	syslog(LOG_DEBUG, "uu_aes_encrypt(): %d", i);
      else
	syslog(LOG_DEBUG, "uu_aes_encrypt(): \"%s\"", tmpbuf2);
#endif
    }
  else
    strncpy(tmpbuf2, string, sizeof(tmpbuf2));
  n=strlen(tmpbuf2)+1;
  /*  Split the string in packets of size PSIZE */
  for (i=0; i<n; i+=PSIZE)
    {
      strncpy(packet,&(tmpbuf2[i]),PSIZE);
      m=n-i;

      /* Fill the last one with random data */
      while (m<PSIZE)
	packet[m++]=rand() % 0x100;

      if (!h || (h && h->encryption==ENCRYPTION_SIMPLE))
	{
	  /* Calculate a new stream key before this cleartext is encrypted */
	  makekey(tmpbuf, sizeof(tmpbuf), lc,
		  CHALLENGE_SIZE, packet, PSIZE);
	  
	  /* Encrypt this packet */
	  for (j=0; j<PSIZE; j++)
	    packet[j]^=lk[j];

	  /* Save the new key */
	  memcpy(lk, tmpbuf, KEYSIZE);
	}

      /* ...and write it to the socket */
      /*      hexdump(stderr, packet, PSIZE);*/
      send(s, packet, PSIZE, 0);

    }
  return 1;
}

/* Get a complete NUL-terminated string withing a specified timeout */
int hlcrypt_Receive(SOCKET s, unsigned char *string, int maxlen, int timeout, HLCRYPT_HANDLE h)
{
  int ready=0;
  int i,j,n;
  unsigned char packet[PSIZE];
  static unsigned char tmpbuf[BUFSIZE];
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

	  if (!h || (h && h->encryption==ENCRYPTION_SIMPLE))
	    {
	      /* Decrypt this packet */
	      for (j=0;j<PSIZE;j++)
		packet[j]^=rk[j];
	      
	      /* Calculate a new stream key */
	      makekey(rk, KEYSIZE, 
		      rc, CHALLENGE_SIZE,
		      packet, PSIZE);
	    }
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
  if (h && (h->encryption==ENCRYPTION_AES))
    {
      memcpy(tmpbuf, string, i);
      i=uu_aes_decrypt(tmpbuf, strlen(tmpbuf), h->aes_key, 256, string, maxlen);
#ifdef DEBUG
      syslog(LOG_DEBUG, "uu_aes_decrypt(\"%s\"): %d", tmpbuf, i);
#endif
    }
  return strlen(string);
}

int hlcrypt_AuthClient(SOCKET csocket, unsigned char *local_key,
		       unsigned char *remote_key, HLCRYPT_HANDLE *h)
{
  char tmpbuf[BUFSIZE], tmpbuf2[SHA_DIGEST_LENGTH];
  char *lc, *lk, *rc, *rk, *p;
  int v,e;
  if (h)
    {
      (*h)=(HLCRYPT_HANDLE)malloc(sizeof(struct hlcrypt_handle_s));
      (*h)->version=INITIAL_VERSION;
      (*h)->encryption=INITIAL_ENCRYPTION;
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
  lc[5]='W';
  lc[12]='h';
  lc[21]='i';
  lc[26]='!';

  /* Write the client challenge to the socket */
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

  if (h)
    {
      memcpy((*h)->aes_key, (*h)->remote_streamkey, 16);
      memcpy((*h)->aes_key+16, (*h)->local_streamkey, 16);
    }

  if ((hlcrypt_Receive(csocket, tmpbuf, BUFSIZE, READ_TIMEOUT, h?(*h):NULL)>0) &&
      (!strncmp(tmpbuf, "OK", 2)))
    {
#ifdef DEBUG
      syslog(LOG_DEBUG, "Received \"%s\"", tmpbuf);
#endif
      tmpbuf[sizeof(tmpbuf)-1]='\0'; /* Guard */
      if (tmpbuf[2]=='{' && (p=strchr(tmpbuf, '}')))
	{
	  if (h)
	    {
#ifdef DEBUG
	      syslog(LOG_DEBUG, "Trying handshake - received \"%s\"", tmpbuf);
#endif
	      *(++p)='\0';
	      if (sscanf(tmpbuf, "OK{%i,%i}", &v, &e)!=2)
		{
		  syslog(LOG_WARNING, "Unparseable \"OK\" string - using default version");
		  v=INITIAL_VERSION;
		  e=INITIAL_ENCRYPTION;
		}
	      if (v > MAX_VERSION)
		v = MAX_VERSION;
	      if (e > MAX_ENCRYPTION)
		e = MAX_ENCRYPTION;
	      sprintf(tmpbuf, "OK{%d,%d}", v, e);
	      hlcrypt_Send(csocket, tmpbuf, (*h));
	      (*h)->version=v;
	      (*h)->encryption=e;
	    }
	  else
	    {
	       sprintf(tmpbuf, "OK{%d,%d}", INITIAL_VERSION, INITIAL_ENCRYPTION);
	       hlcrypt_Send(csocket, tmpbuf, NULL);
	    }
	}
      /*      syslog(LOG_INFO,"Authenticated(%d,%d)",h?(*h)->version:1,h?(*h)->encryption:2);*/
      return 1;
    }
  else
    {
      syslog(LOG_ERR, "No response or wrong response received");
      return 0;
    }
}

int hlcrypt_AuthServer(SOCKET csocket, unsigned char *remote_key,
		       unsigned char *local_key, HLCRYPT_HANDLE *h)
{
  char tmpbuf[BUFSIZE], tmpbuf2[SHA_DIGEST_LENGTH];
  char *lc, *lk, *rc, *rk;
  int handshake=0;
  if (h)
    {
      (*h)=(HLCRYPT_HANDLE)malloc(sizeof(struct hlcrypt_handle_s));
      (*h)->version=INITIAL_VERSION;
      (*h)->encryption=INITIAL_ENCRYPTION;
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

  if (h &&
      tmpbuf[5]=='W' && 
      tmpbuf[12]=='h' && 
      tmpbuf[21]=='i' &&
      tmpbuf[26]=='!')
    {
#ifdef DEBUG
      syslog(LOG_DEBUG, "Will handshake");
#endif
      handshake=1;
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

  if (h && handshake)
    sprintf(tmpbuf, "OK{%d,%d}", MAX_VERSION, MAX_ENCRYPTION);
  else
    strcpy(tmpbuf,"OK");

  hlcrypt_MakeToken(tmpbuf+strlen(tmpbuf),sizeof(tmpbuf)-strlen(tmpbuf));

  if (h)
    {
      memcpy((*h)->aes_key, (*h)->local_streamkey, 16);
      memcpy((*h)->aes_key+16, (*h)->remote_streamkey, 16);
    }

#ifdef DEBUG
  syslog(LOG_DEBUG, "Sending \"%s\"", tmpbuf);
#endif
  
  hlcrypt_Send(csocket,tmpbuf, h?(*h):NULL);

  if (h && handshake)
    {
      if (!hlcrypt_Receive(csocket, tmpbuf, sizeof(tmpbuf), READ_TIMEOUT, (*h)) ||
	  sscanf(tmpbuf, "OK{%i,%i}", &((*h)->version), &((*h)->encryption))!=2 ||
	  (*h)->version > MAX_VERSION || (*h)->encryption>MAX_ENCRYPTION)
	{
	  syslog(LOG_ERR, "Handshake failed");
	  return 0;
	}
    }
  /*  syslog(LOG_INFO,"Authenticated(%d,%d)",h?(*h)->version:1,h?(*h)->encryption:1);*/

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

