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

#ifndef B64_H
#define B64_H

/* Base64 encode/decode */
int b64_encode(unsigned char *indata, int indatalen, char *result, int reslen);
int b64_decode(unsigned char *indata, int indatalen, char *result, int reslen);

#endif
