#ifndef HLCRYPT_H
#define HLCRYPT_H

#include <openssl/sha.h>
#include "hlcrypt.h"

#define CHALLENGE_SIZE 64
#define PSIZE SHA_DIGEST_LENGTH
#define KEYSIZE PSIZE

typedef struct hlcrypt_handle_s
{
  /* Authentication and encryption data */
  unsigned char local_challenge[CHALLENGE_SIZE];
  unsigned char remote_challenge[CHALLENGE_SIZE];
  unsigned char local_streamkey[KEYSIZE];
  unsigned char remote_streamkey[KEYSIZE];
} *HLCRYPT_HANDLE;

/*
  Authentication function for the client side.
  */
int hlcrypt_AuthClient(int csocket,
		       unsigned char *clientkey,
		       unsigned char *serverkey,
		       HLCRYPT_HANDLE *h);

/*
  Authentication function for the server side.
  */
int hlcrypt_AuthServer(int csocket,
		       unsigned char *clientkey,
		       unsigned char *serverkey,
		       HLCRYPT_HANDLE *h);

/*
  Send a string encrypted to the peer
  */
int hlcrypt_Send(int s, unsigned char *string, HLCRYPT_HANDLE h);

/*
  Receive a string from the peer
  */
int hlcrypt_Receive(int s, unsigned char *string, int maxlen, int timeout, HLCRYPT_HANDLE h);

/*
  Create a "token" string
  */
int hlcrypt_MakeToken(char *buf, int bufsize);

/*
  Calculate SHA1() on a block
  */
char *hlcrypt_SHA1(unsigned char *string,int slen);

/*
  Free a handle structure
  */
int hlcrypt_freeHandle(HLCRYPT_HANDLE *h);

#endif
