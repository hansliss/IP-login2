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

#ifndef _UU_AES_H
#define _UU_AES_H

int uu_aes_encrypt(unsigned char *ctext, int ctextsize, unsigned char *key, int keysize, char *outbuf, int outbufsize, unsigned char *ivin);
int uu_aes_decrypt(unsigned char *ctext, int ctextsize, unsigned char *key, int keysize, char *outbuf, int outbufsize);

#endif
