/*
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version
 *   2 of the License, or (at your option) any later version.
 *
 *   Hans Liss <hans.liss@its.uu.se>  Uppsala Universitet
 *
 *   The file LICENSE must accompany this package when redistributed.
 *   Please refer to it for specific acknowledgements.
 *
 */

#include	<stdio.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include <time.h>

#ifndef WIN32
#include	<unistd.h>
#include	<syslog.h>
#include "config.h"
#endif

#ifdef WIN32
#define HAVE_STRING_H 1
#define strcasecmp(a,b) _stricmp((a),(b))
#include <process.h>
#include <io.h>
#endif

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
#include "genseed.h"


/*
	Returnerar ett 16 byte långt slumptal
*/

#ifndef	RANDOM
#ifdef WIN32
#define RANDOM "C:/random.bin"
#else
#define RANDOM  "/var/tmp/random"
#endif
#endif

static	char	* random_file	= RANDOM;

void	set_random_file(char * r)
{
	static	char	the_random_file[255];
	strncpy(the_random_file,r,sizeof(the_random_file)-1);
	random_file = the_random_file;
}

#ifdef WIN32
void syslog(int s, const char *fmt, ...)
{
}
#endif

char	* genseed(void)
{
	int	f;
	time_t	t;
	struct	stat	statbuf;
	char	* p;
	unsigned int	l=0, o;
	MD5_CTX	context;
#define	LSC	128
	unsigned char	secret[LSC];
	static	char	rseed[17];
	time(&t);
	f	= open(random_file,O_RDWR|O_CREAT,0600);
	if (f < 0) {
		syslog(LOG_ERR,"ERROR: genseed(): %.80s, random error %m",
			random_file);
		return	NULL;
	}

	MD5Init(&context);
	MD5Update(&context,(char *) &t, sizeof(t));
	if (stat("/tmp",&statbuf) == 0)
		MD5Update(&context,(char *) &statbuf, sizeof(statbuf));
	if (f >= 0 && (l=read(f,secret,sizeof(secret))) > 0)
		MD5Update(&context,(char *) &secret, sizeof(secret));
	if (stat("/var/spool/mqueue",&statbuf) == 0)
		MD5Update(&context,(char *) &statbuf, sizeof(statbuf));
	MD5Update(&context,(char *) &statbuf, sizeof(statbuf));
	if (f >= 0) {
		if (l < (LSC-16)) { 
			MD5Final(&secret[l],&context);
			l+= 16;
			write(f,secret,sizeof(secret));
		}
		else {
			o = (secret[0] >> 1) % (LSC-16);
			o = (secret[o] >> 1) % (LSC-16);
			MD5Final(&secret[o],&context);
			lseek(f,o,SEEK_SET); 
			write(f,&secret[1],sizeof(secret));
			l = LSC;
		}
		close(f);
		MD5Init(&context);
		MD5Update(&context, secret, l);
		MD5Update(&context, secret, l);
		MD5Final(rseed,&context);
	}
	else {
		memcpy(rseed,secret,16);
	}
	for (p=rseed,l=0; l<16; l++,p++) {
		*p = *p & 0x7f;
		if (*p <= ' ') *p += ' ';
		if (*p == ';') *p = 'Y';
		if (*p == 0x7f) *p = 'Z';
	}
	rseed[16]=0;
	return	rseed;
}
#ifdef	GENSEED_DEBUG
int	main()
{
	int	i;
	char	* c;
	for (i=0; i<24; i++) {
		c	= genseed();
		if (c == NULL) break;
		printf("%.17s\n",c);
	}
	return	i < 24;
}
#endif
