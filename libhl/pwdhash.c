#include <stdlib.h>

#ifndef WIN32
#include "config.h"
#endif

#if HAVE_CRYPT_H==1
#include <crypt.h>
#endif

#ifndef WIN32
#define __USE_XOPEN
#include <unistd.h>
#else
#define HAVE_STRING_H 1
#define strcasecmp(a,b) _stricmp((a),(b))
#endif

#include "hl.h"
#if HAVE_STRINGS_H==1
#include <strings.h>
#endif
#if HAVE_STRING_H==1
#include <string.h>
#endif


#ifndef MD4_DIGEST_LENGTH
#define MD4_DIGEST_LENGTH 16
#endif
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#define SALTLEN 6

#define BUFSIZE 8192

int pwdcheck(char *hashed, char *passwd)
{
  static char algorithm[BUFSIZE], hash[BUFSIZE];
  SHA1Context sha_ctx;
  MD5_CTX md5_ctx;
  int len;
  static char SALT[BUFSIZE];
  static char tmpbuf[BUFSIZE], tmpbuf2[BUFSIZE];
  
  if (!hashed)
    return (passwd?1:0);
  if (!passwd)
    return 2;

  if (sscanf(hashed, "{%127[^}]}%127s", algorithm, hash)!=2)
    {
      strcpy(algorithm, "crypt");
      strncpy(hash, hashed, sizeof(hash));
      hash[sizeof(hash)-1]='\0';
    }
  if (!strcasecmp(algorithm, "crypt"))
    {
      SALT[0]=hash[0];
      SALT[1]=hash[1];
      SALT[2]='\0';
      return (strcmp(crypt(passwd, SALT), hash)?1:0);
    }
  else if (!strcasecmp(algorithm, "md5"))
    {
      if (!(len=b64_decode(hash, strlen(hash), tmpbuf2, sizeof(tmpbuf2))) || (len!=MD5_DIGEST_LENGTH))
	{
	  return -1;
	}
      MD5Init(&md5_ctx);
      MD5Update(&md5_ctx, passwd, strlen(passwd));
      MD5Final(tmpbuf, &md5_ctx);
      return (memcmp(tmpbuf, tmpbuf2, MD5_DIGEST_LENGTH)?1:0);
    }
  else if (!strcasecmp(algorithm, "sha"))
    {
      if (!(len=b64_decode(hash, strlen(hash), tmpbuf2, sizeof(tmpbuf2))) || (len!=SHA_DIGEST_LENGTH))
	return -1;
      SHA1Reset(&sha_ctx);
      SHA1Input(&sha_ctx, passwd, strlen(passwd));
      SHA1Result(&sha_ctx, tmpbuf);
      return (memcmp(tmpbuf, tmpbuf2, SHA_DIGEST_LENGTH)?1:0);
    }
  else if (!strcasecmp(algorithm, "smd5"))
    {
      if (!(len=b64_decode(hash, strlen(hash), tmpbuf2, sizeof(tmpbuf2))) || (len<MD5_DIGEST_LENGTH))
	return -1;
      len-=MD5_DIGEST_LENGTH;
      if (len >= sizeof(SALT))
	return -2;
      if (len)
	memcpy(SALT, &(tmpbuf2[MD5_DIGEST_LENGTH]), len);
      MD5Init(&md5_ctx);
      MD5Update(&md5_ctx, passwd, strlen(passwd));
      MD5Update(&md5_ctx, SALT, len);
      MD5Final(tmpbuf, &md5_ctx);
      return (memcmp(tmpbuf, tmpbuf2, MD5_DIGEST_LENGTH)?1:0);
    }
  else if (!strcasecmp(algorithm, "ssha"))
    {
      if (!(len=b64_decode(hash, strlen(hash), tmpbuf2, sizeof(tmpbuf2))) || (len<SHA_DIGEST_LENGTH))
	return -1;
      len-=SHA_DIGEST_LENGTH;
      if (len >= sizeof(SALT))
	return -2;
      if (len)
	memcpy(SALT, &(tmpbuf2[SHA_DIGEST_LENGTH]), len);
      SHA1Reset(&sha_ctx);
      SHA1Input(&sha_ctx, passwd, strlen(passwd));
      SHA1Input(&sha_ctx, SALT, len);
      SHA1Result(&sha_ctx, tmpbuf);
      return (memcmp(tmpbuf, tmpbuf2, SHA_DIGEST_LENGTH)?1:0);
    }
  else
    {
      return -1;
    }
}

int hlcrypt_makePwdHash(char *algorithm, char *passwd, char *outbuf, int outbuflen)
{
  SHA1Context sha_ctx;
  MD5_CTX md5_ctx;
  int i;
  char *rnd;
  static char SALT[BUFSIZE];
  static char tmpbuf[BUFSIZE];

  memset(outbuf, 0, outbuflen);
  if (!algorithm)
    {
      algorithm="crypt";
    }

  if (!outbuf)
    return 2;

  if (!strcasecmp(algorithm, "crypt"))
    {
      rnd=genseed();
      SALT[0]=(rnd[0] % 26) + 'A';
      SALT[1]=(rnd[1] % 26) + 'A';
      SALT[2]='\0';
      strcpy(outbuf, "{crypt}");
      strncpy(outbuf+7, crypt(passwd, SALT), outbuflen-8);
      return 0;
    }
  else if (!strcasecmp(algorithm, "md5"))
    {
      MD5Init(&md5_ctx);
      MD5Update(&md5_ctx, passwd, strlen(passwd));
      MD5Final(tmpbuf, &md5_ctx);
      strncpy(outbuf, "{md5}", outbuflen-1);
      return b64_encode(tmpbuf, MD5_DIGEST_LENGTH, outbuf+5, outbuflen-6)?0:1;
    }
  else if (!strcasecmp(algorithm, "sha"))
    {
      SHA1Reset(&sha_ctx);
      SHA1Input(&sha_ctx, passwd, strlen(passwd));
      SHA1Result(&sha_ctx, tmpbuf);
      strncpy(outbuf, "{sha}", outbuflen-1);
      return b64_encode(tmpbuf, SHA_DIGEST_LENGTH, outbuf+5, outbuflen-6)?0:1;
    }
  else if (!strcasecmp(algorithm, "smd5"))
    {
      rnd=genseed();
      for (i=0; i<SALTLEN; i++)
	SALT[i]=rnd[i];
      SALT[i]='\0';
      MD5Init(&md5_ctx);
      MD5Update(&md5_ctx, passwd, strlen(passwd));
      MD5Update(&md5_ctx, SALT, SALTLEN);
      MD5Final(tmpbuf, &md5_ctx);
      memcpy(tmpbuf+MD5_DIGEST_LENGTH, SALT, SALTLEN);
      strncpy(outbuf, "{smd5}", outbuflen-1);
      return b64_encode(tmpbuf, MD5_DIGEST_LENGTH + SALTLEN, outbuf+6, outbuflen-7)?0:1;
    }
  else if (!strcasecmp(algorithm, "ssha"))
    {
      rnd=genseed();
      for (i=0; i<SALTLEN; i++)
	SALT[i]=rnd[i];
      SALT[i]='\0';
      SHA1Reset(&sha_ctx);
      SHA1Input(&sha_ctx, passwd, strlen(passwd));
      SHA1Input(&sha_ctx, SALT, SALTLEN);
      SHA1Result(&sha_ctx, tmpbuf);
      memcpy(tmpbuf+SHA_DIGEST_LENGTH, SALT, SALTLEN);
      strncpy(outbuf, "{ssha}", outbuflen-1);
      return b64_encode(tmpbuf, SHA_DIGEST_LENGTH + SALTLEN, outbuf+6, outbuflen-7)?0:1;
    }
  else
    {
      return -1;
    }
}
