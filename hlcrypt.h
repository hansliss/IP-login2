#ifndef HLCRYPT_H
#define HLCRYPT_H

#include "makeaddress.h"
#include "sha1.h"

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH SHA1HashSize
#endif

#ifndef MD4_DIGEST_LENGTH
#define MD4_DIGEST_LENGTH 16
#endif

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

#define PSIZE SHA_DIGEST_LENGTH
#define KEYSIZE PSIZE

#define CHALLENGE_SIZE 64

#define ENCRYPTION_NONE 0
#define ENCRYPTION_SIMPLE 1
#define ENCRYPTION_AES 2

#define INITIAL_VERSION 1
#define INITIAL_ENCRYPTION ENCRYPTION_SIMPLE

#define MAX_VERSION 2
#define MAX_ENCRYPTION ENCRYPTION_AES

typedef struct hlcrypt_handle_s
{
  int version;
  int encryption;
  /* Authentication and encryption data */
  unsigned char local_challenge[CHALLENGE_SIZE];
  unsigned char remote_challenge[CHALLENGE_SIZE];
  unsigned char local_streamkey[KEYSIZE];
  unsigned char remote_streamkey[KEYSIZE];
  unsigned char aes_key[32];
} *HLCRYPT_HANDLE;

/*
  Authentication function for the client side.
  */
int hlcrypt_AuthClient(SOCKET csocket,
		       unsigned char *clientkey,
		       unsigned char *serverkey,
		       HLCRYPT_HANDLE *h);

/*
  Authentication function for the server side.
  */
int hlcrypt_AuthServer(SOCKET csocket,
		       unsigned char *clientkey,
		       unsigned char *serverkey,
		       HLCRYPT_HANDLE *h);

/*
  Send a string encrypted to the peer
  */
int hlcrypt_Send(SOCKET s, unsigned char *string, HLCRYPT_HANDLE h);

/*
  Receive a string from the peer
  */
int hlcrypt_Receive(SOCKET s, unsigned char *string, int maxlen, int timeout, HLCRYPT_HANDLE h);

/*
  Create a "token" string
  */
int hlcrypt_MakeToken(char *buf, int bufsize);

/*
  Calculate MD4, MD5 and SHA1 hashes on a block
  */
char *hlcrypt_MD4(unsigned char *string,int slen);
char *hlcrypt_MD5(unsigned char *string,int slen);
char *hlcrypt_SHA1(unsigned char *string,int slen);

/*
  Free a handle structure
  */
int hlcrypt_freeHandle(HLCRYPT_HANDLE *h);

#endif
