#ifndef LIBDIV_H
#define LIBDIV_H

#include <arpa/inet.h>
#include <stdio.h>

void hexdump(FILE *fd, char *buf, int n);

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
  Add a attribute/value pair to the list 'vars' (in/out).
  'name' and 'value' are in parameters and their contents
  will be copied.
  */
void addvar(varlist *vars, char *name, char *value);

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
#ifndef HLCRYPT_H
#define HLCRYPT_H

#if HAVE_LIBCRYPTO == 1
#include <openssl/sha.h>

#define PSIZE SHA_DIGEST_LENGTH
#define KEYSIZE PSIZE

#define CHALLENGE_SIZE 64

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

#endif
