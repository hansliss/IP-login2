#include <stdio.h>
#include <time.h>
#include <sys/types.h>

#ifdef WIN32
#include <winsock2.h>
#define strcasecmp(a,b) _stricmp((a),(b))
#define strncasecmp(a,b,c) _strnicmp((a),(b),(c))
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include "config.h"
#endif

#if HAVE_STRINGS_H==1
#include <strings.h>
#endif
#if HAVE_STRING_H==1
#include <string.h>
#endif
#include "hl.h"
#include "rijndael-api-fst.h"

#define BUFSIZE 8192

#define KEYLEN 32
#define IVLEN 16

#define BLOCKSIZE 16
#define TAG "{aes-256-cbc}"

int uu_aes_encrypt(unsigned char *ctext, int ctextsize, unsigned char *key, int keysize, char *outbuf, int outbufsize)
{
  int l, i, r;
  time_t now;
  static char resbuf[BUFSIZE], b64buf[BUFSIZE];
  static char tmpbuf[BUFSIZE];
  static unsigned char iv[IVLEN];
  static char ivstring[33];
  static char keystring[65];

  keyInstance key_i;
  cipherInstance cipher_i;

  if (keysize != KEYLEN * 8) /* We accept only 256-bit keys */
    return -1;

  if (!ctext || !ctextsize || !outbuf)
    return -2;

#ifdef DEBUG
  fprintf(stderr, "Encryption key:\n");
  hexdump(stderr, key, keysize/8);
#endif

  l=ctextsize;
  if (l>BUFSIZE)
    return -2;

  /* Try to make sure that there is enough space in the result buffer */
  if (outbufsize < (int)(4*(IVLEN +
		      ctextsize +
		      BLOCKSIZE - (ctextsize % BLOCKSIZE))/3 +
		    strlen(TAG) + 1))
    return -3;

  /* Construct an IV, by mapping in a four-byte timestamp and padding with random data */
  time(&now);
  now=htonl(now);
  memcpy(iv, (unsigned char*)(&now), sizeof(now));
  memcpy(iv+sizeof(now), genseed(), IVLEN-sizeof(now));

  /* Expand the binary key to an ASCII hex string */
  for (i=0; i < keysize/8; i++)
    sprintf(&(keystring[i*2]), "%02x", key[i]);

  /* Expand the binary IV to an ASCII hex string */
  for (i=0; i< IVLEN; i++)
    sprintf(&(ivstring[i*2]), "%02x", iv[i]);

#ifdef DEBUG_AES
  printf("Key: [%s]\n", keystring);
  printf("IV: [%s]\n", ivstring);
  printf("CT (%d chars): \"%s\"\n", ctextsize, ctext);
  printf("Cipher: %s\n", TAG);
#endif

  /* Initialize the key struct */
  if ((r=makeKey(&key_i, DIR_ENCRYPT, keysize, keystring))!=TRUE)
    return -4;

  /* Initialize the cipher struct */
  if ((r=cipherInit(&cipher_i, MODE_CBC, ivstring))!=TRUE)
    return -5;

  /* Copy the IV to the result buffer */
  memcpy(resbuf, iv, IVLEN);

  /* Copy the cleartext string to tmpbuf, to pad it */
  strncpy(tmpbuf, ctext, sizeof(tmpbuf));

  /* Pad according to PKCS#5 */
  for (i=0; i < BLOCKSIZE - (ctextsize % BLOCKSIZE); i++)
    tmpbuf[ctextsize + i] = BLOCKSIZE - (ctextsize % BLOCKSIZE);

  /*
    Compute the total length including padding -
    now an integral number of blocks
    */
  l = ctextsize + BLOCKSIZE - (ctextsize % BLOCKSIZE);

  /* Encrypt the buffer, placing the result *after* the IV in resbuf */
  l=blockEncrypt(&cipher_i, &key_i, tmpbuf, l*8, &(resbuf[IVLEN]));

  /* blockEncrypt() returns length in bits */

  /* Total result length is IVLEN plus length in bytes */
  l= l / 8 + IVLEN;

  /* Base64 encode the result */
  b64_encode(resbuf, l, b64buf, sizeof(b64buf));

  /* Add a tag and copy it all to the outbuf */
  sprintf(outbuf, "%s%s", TAG, b64buf);
  return 0;
}

int uu_aes_decrypt(unsigned char *ctext, int ctextsize, unsigned char *key, int keysize, char *outbuf, int outbufsize)
{
  int l, i, r, padl;
  static char resbuf[BUFSIZE];
  static char tmpbuf[BUFSIZE];
  static unsigned char iv[IVLEN];
  static char ivstring[33];
  static char keystring[65];

  keyInstance key_i;
  cipherInstance cipher_i;

  if (keysize != KEYLEN * 8)
    return -1;

  if (!ctext || !ctextsize || !outbuf)
    return -2;

#ifdef DEBUG
  fprintf(stderr, "Decryption key:\n");
  hexdump(stderr, key, keysize/8);
#endif

  /* Verify that the tag is correct */
  if (strncasecmp(ctext, TAG, strlen(TAG)))
    return -31;

  l=ctextsize;
  
  /* Try to make sure that the result buffer is large enough */
  if (outbufsize < (int)(3*(ctextsize - strlen(TAG))/4 - IVLEN + 1))
    return -3;

  if (ctextsize > BUFSIZE)
    return -32;

  /* Unpack the Base64 data */
  if (!(l=b64_decode(ctext + strlen(TAG), ctextsize - strlen(TAG), tmpbuf, sizeof(tmpbuf))))
    return -33;

  /* Extract the IV */
  memcpy(iv, tmpbuf, IVLEN);

  
  /* Expand the binary key to an ASCII hex string */
  for (i=0; i < keysize/8; i++)
    sprintf(&(keystring[i*2]), "%02x", key[i]);

  /* Expand the binary IV to an ASCII hex string */
  for (i=0; i< IVLEN; i++)
    sprintf(&(ivstring[i*2]), "%02x", iv[i]);

#ifdef DEBUG_AES
  printf("Key: [%s]\n", keystring);
  printf("IV: [%s]\n", ivstring);
  printf("Cipher: %s\n", TAG);
#endif

  /* ciphertext length is length of decoded data minus length of the IV */
  l-=IVLEN;

  
  /* Initialize the key struct */
  if ((r=makeKey(&key_i, DIR_DECRYPT, keysize, keystring))!=TRUE)
    return -4;

  /* Initialize the cipher struct */
  if ((r=cipherInit(&cipher_i, MODE_CBC, ivstring))!=TRUE)
    return -5;

  /* Decrypt the data */
  l=blockDecrypt(&cipher_i, &key_i, tmpbuf+IVLEN, l*8, resbuf);

  /* blockDecrypt() returns length in bits */
  l /= 8;

  /* Verify and remove the padding */
  padl=resbuf[l-1];
  for (i=0; i<padl; i++)
    {
      if (resbuf[l-padl+i] != padl)
	return -34;
      else
	resbuf[l-padl+i]='\0';
    }
  l-=padl;

  /* Copy the final result to the outbuf */
  strncpy(outbuf, resbuf, l+1);

  return 0;
}
