#include	<stdio.h>
#include	<sys/stat.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<syslog.h>
#include <time.h>
#include <string.h>

#include "config.h"
#include "hl.h"


/*
	Returnerar ett 16 byte långt slumptal
*/

#ifndef	RANDOM
#define	RANDOM	"/var/tmp/random"
#endif

static	char	* random_file	= RANDOM;

void	set_random_file(char * r)
{
	static	char	the_random_file[255];
	strncpy(the_random_file,r,sizeof(the_random_file)-1);
	random_file = the_random_file;
}


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
