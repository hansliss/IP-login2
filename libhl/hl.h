#ifndef LIBDIV_H
#define LIBDIV_H

#ifdef WIN32
extern void syslog(int s, const char *fmt, ...);
#define LOG_ERR 0
#define LOG_DEBUG 1
#define LOG_NOTICE 2
#define LOG_INFO 3
#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <winsock2.h>
#include <io.h>
#else
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define SOCKET int
#endif


#include <stdio.h>


void hexdump(FILE *fd, unsigned char *buf, int n);

/* Translate a dotted quad or a hostname to an IP address if
   possible. Return 0 if it fails, non-0 otherwise */
int makeaddress(char *name_or_ip, struct in_addr *res);

/* Translate a service name or port number (as a string) into an NBO
   integer. Return 0 on failure. */
int makeport(char *name_or_port);

/* Remove junk characters from a string for logging and stuff */
void dejunkifyforlog(char *s);

/*
  Remove all blanks at the beginning and end of the string 'string' (in/out).
  */
void cleanupstring(char *string);

/*
  Chop off all whitespace characters (including newline characters etc)
  from the end of the string 'string' (in/out).
  */
void chop(char *string);

/* Base64 encode/decode */
int b64_encode(unsigned char *indata, int indatalen, char *result, int reslen);
int b64_decode(unsigned char *indata, int indatalen, char *result, int reslen);

#endif
#ifndef VARLIST_H
#define VARLIST_H

/********************************

 A list node for handling variable lists and
 functions to make use of it

********************************/

typedef struct varnode
{
  char *name;
  char *value;
  struct varnode *next;
} *varlist;

/*
  Add an attribute/value pair to the list 'vars' (in/out).
  'name' and 'value' are in parameters and their contents
  will be copied.
  */
void addvar(varlist *vars, char *name, char *value);

/*
  Change or add an attribute value. See addvar().
  */
void setvar(varlist *vars, char *name, char *value);

/*
  Find and return a node in 'vars' (in) with the
  attribute name 'name' (in).
  */
char *findvar(varlist vars, char *name);

/*
  Release all memory allocated for the list 'vars' (in/out) and
  set it to NULL.
  */
void freevarlist(varlist *vars);


/*******************************

 Another list node for handling simple name lists.
 Very useful for splitstring().

 *******************************/

typedef struct namenode
{
  char *name;
  struct namenode *next;
} *namelist;

/*
  Add a new name node to 'names' (in/out) with the name 'name' (in).
  'name' will be copied.
  */
void addname(namelist *names, char *name);

/*
  Add a new name node to the front of 'names' (in/out) with the name 'name' (in).
  'name' will be copied.
  */
void addname_front(namelist *names, char *name);

/*
  Find and return a node in 'names' (in) with the name 'name' (in)
  and return it, or NULL if nothing found.
  */
int findname(namelist names, char *name);

/*
  Release all memory allocated for the list 'names' (in/out) and
  set it to NULL.
  */
void freenamelist(namelist *names);

/*
  Split the string 'string' (in) into components using the delimiter
  'splitter' (in). Add the components to 'substrings' (in/out), which
  must be initialized prior to calling this function.
  The substrings will be cleaned up with cleanupstring() (see below).
  */
int splitstring(char *string, char splitter, namelist *substrings);

#endif
#ifndef CONFFILE_H
#define CONFFILE_H

/*********************************
 *
 *
 * Functions for iterating over entries of a specific type
 *
 *
 *********************************/


/*
  Open the file named by 'conffilename' (in) or rewind it if open.

  Returns 0 for failure and !=0 for success
  */
int conf_init(char *conffilename);

/*
  Rewind the current file.
  */
void conf_rewind();

/*
  Get the next entry of type 'type' (in) and return the name in
  'label' (in/out) of max size 'labelsize' (in). Return all attributes
  in 'vars' (in/out).

  Returns 0 for failure or EOF and !=0 for success
  */
int conf_next(char *type, char *label, int labelsize, varlist *vars);

/*
  Close the configuration file and do any additional cleaning up.
  */
int conf_cleanup();

/**********************************/

/**********************************
 *
 *
 * Functions for searching for or changind configuration data
 *
 *
 **********************************/
 
/*
  Find an entry of type 'type' (in) and with then name 'label' (in) in then
  configuration file named by 'conffilename' (in) and return its attributes in
  'vars' (in/out).

  Returns 0 for failure and !=0 for success
  */
int conf_find(char *conffilename, char *type, char *label, varlist *vars);

/*
  Find all entries of type 'type' (in) in the file named by 'conffilename' (in)
  which has 'value' (in) as the value of its attribute 'varname' (in).
  Returns the list of entries in 'names' (in/out).

  Returns 0 for failure and !=0 for success
  */
int conf_matchlist(char *conffilename, char *type, char *varname,
		   char *value, namelist *names);
int conf_getvar(char *conffilename, char *type, char *label,
		char *varname, char *varvalue, int maxlen);
int conf_set(char *conffilename, char *type, char *label,
	     char *name, char *value);


#endif

#ifndef GENSEED_H
#define GENSEED_H
void	set_random_file(char * r);
char	*genseed(void);
#endif

/* GLOBAL.H - RSAREF types and constants
 */

/* PROTOTYPES should be set to one if and only if the compiler supports
   function argument prototyping.
   The following makes PROTOTYPES default to 0 if it has not already
   been defined with C compiler flags.
 */

#ifndef _RSAREF_GLOBAL_H
#define _RSAREF_GLOBAL_H

#ifndef PROTOTYPES
#define PROTOTYPES 1
#endif

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
   If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
   returns an empty list.
 */

#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

#endif
/* MD4.H - header file for MD4C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
   rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD4 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD4 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

#ifndef _MD4_H
#define _MD4_H

/* MD4 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD4_CTX;

void MD4Init PROTO_LIST ((MD4_CTX *));
void MD4Update PROTO_LIST
  ((MD4_CTX *, unsigned char *, unsigned int));
void MD4Final PROTO_LIST ((unsigned char [16], MD4_CTX *));

#endif
/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#ifndef _MD5_H
#define _MD5_H

/* MD5 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void MD5Init PROTO_LIST ((MD5_CTX *));
void MD5Update PROTO_LIST
  ((MD5_CTX *, unsigned char *, unsigned int));
void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));

#endif
/*
 *  sha1.h
 *
 *  Description:
 *      This is the header file for code which implements the Secure
 *      Hashing Algorithm 1 as defined in FIPS PUB 180-1 published
 *      April 17, 1995.
 *
 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 */

#ifndef _SHA1_H_
#define _SHA1_H_

#ifndef WIN32
#include <inttypes.h>
#endif

/*
 * If you do not have the ISO standard stdint.h header file, then you
 * must typdef the following:
 *    name              meaning
 *  uint32_t         unsigned 32 bit integer
 *  uint8_t          unsigned 8 bit integer (i.e., unsigned char)
 *  int_least16_t    integer of >= 16 bits
 *
 */

#ifndef _SHA_enum_
#define _SHA_enum_
enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result */
};
#endif
#define SHA1HashSize 20

#ifdef WIN32
typedef unsigned long uint32_t;
typedef short int_least16_t;
typedef unsigned char uint8_t;
#endif

/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct SHA1Context
{
    uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest  */

    uint32_t Length_Low;            /* Message length in bits      */
    uint32_t Length_High;           /* Message length in bits      */

                               /* Index into message block array   */
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];      /* 512-bit message blocks      */

    int Computed;               /* Is the digest computed?         */
    int Corrupted;             /* Is the message digest corrupted? */
} SHA1Context;

/*
 *  Function Prototypes
 */

int SHA1Reset(  SHA1Context *);
int SHA1Input(  SHA1Context *,
                const uint8_t *,
                unsigned int);
int SHA1Result( SHA1Context *,
                uint8_t Message_Digest[SHA1HashSize]);

#endif

#ifndef HLCRYPT_H
#define HLCRYPT_H

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

#ifndef _PWDHASH_H
#define _PWDHASH_H

int pwdcheck(char *hashed, char *passwd);
int hlcrypt_makePwdHash(char *algorithm, char *passwd, char *outbuf, int outbuflen);

#endif

#ifndef _UU_AES_H
#define _UU_AES_H

int uu_aes_encrypt(unsigned char *ctext, int ctextsize, unsigned char *key, int keysize, char *outbuf, int outbufsize);
int uu_aes_decrypt(unsigned char *ctext, int ctextsize, unsigned char *key, int keysize, char *outbuf, int outbufsize);

#endif
